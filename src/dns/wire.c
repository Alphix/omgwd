// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"

struct reader {
	const uint8_t *buf;
	size_t len;
	size_t pos;
};

static bool rd_u16(struct reader *r, uint16_t *v)
{
	if (r->pos + 2 > r->len)
		return false;
	*v = (r->buf[r->pos] << 8) | r->buf[r->pos + 1];
	r->pos += 2;
	return true;
}

static bool rd_u32(struct reader *r, uint32_t *v)
{
	if (r->pos + 4 > r->len)
		return false;
	*v = ((uint32_t)r->buf[r->pos] << 24) | (r->buf[r->pos + 1] << 16) |
	     (r->buf[r->pos + 2] << 8) | r->buf[r->pos + 3];
	r->pos += 4;
	return true;
}

/*
 * Read a possibly compressed name starting at r->pos into out (uncompressed
 * wire format). Advances r->pos past the name as it appears in the message.
 */
static int rd_name(struct reader *r, uint8_t *out)
{
	size_t pos = r->pos, o = 0, end = 0;
	unsigned int hops = 0;
	size_t min_ptr = r->pos; /* pointers must point before this */

	while (true) {
		uint8_t l;

		if (pos >= r->len)
			return -1;

		l = r->buf[pos];

		if ((l & 0xc0) == 0xc0) {
			size_t target;

			if (pos + 1 >= r->len || ++hops > 64)
				return -1;

			target = ((l & 0x3f) << 8) | r->buf[pos + 1];
			if (target >= min_ptr)
				return -1;

			if (!end)
				end = pos + 2;

			min_ptr = target;
			pos = target;
			continue;
		}

		if (l & 0xc0)
			return -1; /* extended label types are obsolete */

		if (pos + 1 + l > r->len || o + 1 + l > DNAME_MAX)
			return -1;

		memcpy(out + o, r->buf + pos, l + 1);
		o += l + 1;
		pos += l + 1;

		if (!l)
			break;
	}

	r->pos = end ? end : pos;
	return o;
}

/* Copy RDATA, decompressing embedded names of types where that is allowed. */
static bool rd_rdata(struct reader *r, uint16_t type, uint16_t rdlen,
		     uint8_t **out, uint16_t *outlen)
{
	size_t start = r->pos, end = r->pos + rdlen;
	uint8_t tmp[DNS_MAX_UDP * 2 + 2 * (DNAME_MAX + 1)];
	struct reader sub;
	size_t o = 0;
	int n;

	if (end > r->len)
		return false;

	if (!rr_type_has_names(type)) {
		*out = malloc(rdlen ? rdlen : 1);
		if (!*out)
			return false;
		memcpy(*out, r->buf + start, rdlen);
		*outlen = rdlen;
		r->pos = end;
		return true;
	}

	/* names may point anywhere earlier in the message: parse with full buffer */
	sub = *r;
	sub.len = end;

#define NAME()                              \
	do {                                \
		n = rd_name(&sub, tmp + o); \
		if (n < 0)                  \
			return false;       \
		o += n;                     \
	} while (0)
#define CHARSTR()                            \
	do {                                 \
		if (sub.pos >= end)          \
			return false;        \
		FIXED(1 + sub.buf[sub.pos]); \
	} while (0)
#define FIXED(len)                                                    \
	do {                                                          \
		if (sub.pos + (len) > end || o + (len) > sizeof(tmp)) \
			return false;                                 \
		memcpy(tmp + o, sub.buf + sub.pos, (len));            \
		o += (len);                                           \
		sub.pos += (len);                                     \
	} while (0)

	switch (type) {
	case DNS_T_NS:
	case DNS_T_MD:
	case DNS_T_MF:
	case DNS_T_CNAME:
	case DNS_T_MB:
	case DNS_T_MG:
	case DNS_T_MR:
	case DNS_T_PTR:
	case DNS_T_DNAME:
		NAME();
		break;
	case DNS_T_SOA:
		NAME();
		NAME();
		FIXED(20);
		break;
	case DNS_T_MINFO:
	case DNS_T_RP:
		NAME();
		NAME();
		break;
	case DNS_T_MX:
	case DNS_T_AFSDB:
	case DNS_T_RT:
	case DNS_T_KX:
		FIXED(2);
		NAME();
		break;
	case DNS_T_PX:
		FIXED(2);
		NAME();
		NAME();
		break;
	case DNS_T_SRV:
		FIXED(6);
		NAME();
		break;
	case DNS_T_NAPTR:
		FIXED(4);
		CHARSTR(); /* flags */
		CHARSTR(); /* services */
		CHARSTR(); /* regexp */
		NAME();
		break;
	case DNS_T_A6: {
		/* prefix length, address suffix, prefix name (if prefix length > 0) */
		unsigned int plen;

		if (sub.pos >= end)
			return false;
		plen = sub.buf[sub.pos];
		if (plen > 128)
			return false;
		FIXED(1 + (128 - plen + 7) / 8);
		if (plen)
			NAME();
		break;
	}
	default:
		return false;
	}
#undef NAME
#undef CHARSTR
#undef FIXED

	if (sub.pos != end)
		return false;

	*out = malloc(o);
	if (!*out)
		return false;

	memcpy(*out, tmp, o);
	*outlen = o;
	r->pos = end;

	return true;
}

static bool parse_opt(struct dns_msg *m, uint16_t udp_size, uint32_t ttl,
		      const uint8_t *rdata, uint16_t rdlen)
{
	size_t pos = 0;

	if (m->edns.present)
		return false; /* only one OPT allowed */

	m->edns.present = true;
	m->edns.udp_size = udp_size < DNS_MAX_UDP ? DNS_MAX_UDP : udp_size;
	m->edns.ext_rcode = ttl >> 24;
	m->edns.version = (ttl >> 16) & 0xff;
	m->edns.do_bit = !!(ttl & EDNS_DO);

	while (pos + 4 <= rdlen) {
		uint16_t code = (rdata[pos] << 8) | rdata[pos + 1];
		uint16_t len = (rdata[pos + 2] << 8) | rdata[pos + 3];

		pos += 4;
		if (pos + len > rdlen)
			return false;

		switch (code) {
		case EDNS_OPT_EDE:
			if (len >= 2)
				m->edns.ede = (rdata[pos] << 8) |
					      rdata[pos + 1];
			break;
		case EDNS_OPT_MAC:
			if (len == 6) {
				memcpy(m->edns.mac, rdata + pos, 6);
				m->edns.has_mac = true;
			}
			break;
		default:
			break;
		}

		pos += len;
	}

	return pos == rdlen;
}

void dns_msg_init(struct dns_msg *m)
{
	memset(m, 0, sizeof(*m));
	rr_list_init(&m->an);
	rr_list_init(&m->ns);
	rr_list_init(&m->ar);
	m->edns.ede = DNS_EDE_NONE;
}

void dns_msg_free(struct dns_msg *m)
{
	free(m->qd);
	m->qd = NULL;
	m->n_qd = 0;
	rr_list_free(&m->an);
	rr_list_free(&m->ns);
	rr_list_free(&m->ar);
}

bool wire_peek_id(const uint8_t *buf, size_t len, uint16_t *id)
{
	if (len < DNS_HDR_LEN)
		return false;

	*id = (buf[0] << 8) | buf[1];
	return true;
}

bool wire_parse(const uint8_t *buf, size_t len, struct dns_msg *m,
		bool question_only)
{
	struct reader r = { .buf = buf, .len = len };
	uint16_t qd, counts[3];
	struct rr_list *lists[3] = { &m->an, &m->ns, &m->ar };

	dns_msg_init(m);

	if (!rd_u16(&r, &m->id) || !rd_u16(&r, &m->flags) || !rd_u16(&r, &qd) ||
	    !rd_u16(&r, &counts[0]) || !rd_u16(&r, &counts[1]) ||
	    !rd_u16(&r, &counts[2]))
		return false;

	if (qd > DNS_MAX_QUESTIONS)
		return false;

	if (qd) {
		m->qd = calloc(qd, sizeof(*m->qd));
		if (!m->qd)
			return false;

		for (unsigned int i = 0; i < qd; i++) {
			struct dns_question *q = &m->qd[i];

			if (rd_name(&r, q->name) < 0 || !rd_u16(&r, &q->type) ||
			    !rd_u16(&r, &q->class))
				goto error;
			m->n_qd++;
		}

		memcpy(m->qname, m->qd[0].name, sizeof(m->qname));
		m->qtype = m->qd[0].type;
		m->qclass = m->qd[0].class;
		m->has_question = true;
	}

	for (int s = 0; s < 3; s++) {
		/* a query only carries OPT in the additional section */
		if (question_only && s < 2 && counts[s])
			return false;

		for (unsigned int i = 0; i < counts[s]; i++) {
			uint8_t name[DNAME_MAX + 1];
			uint16_t type, class, rdlen, outlen = 0;
			uint32_t ttl;
			uint8_t *rdata = NULL;
			struct dns_rr *rr;

			if (rd_name(&r, name) < 0 || !rd_u16(&r, &type) ||
			    !rd_u16(&r, &class) || !rd_u32(&r, &ttl) ||
			    !rd_u16(&r, &rdlen))
				goto error;

			if (type == DNS_T_OPT) {
				if (s != 2 || name[0] != 0 ||
				    r.pos + rdlen > r.len ||
				    !parse_opt(m, class, ttl, r.buf + r.pos,
					       rdlen))
					goto error;
				r.pos += rdlen;
				continue;
			}

			if (question_only) {
				/* skip anything else (e.g. TSIG) in queries */
				if (r.pos + rdlen > r.len)
					goto error;
				r.pos += rdlen;
				continue;
			}

			if (!rd_rdata(&r, type, rdlen, &rdata, &outlen))
				goto error;

			rr = rr_list_add(lists[s], name, type, class, ttl, NULL,
					 0);
			if (!rr) {
				free(rdata);
				goto error;
			}

			rr->rdata = rdata;
			rr->rdlen = outlen;
		}
	}

	/* trailing garbage is tolerated, as most implementations do */
	return true;

error:
	dns_msg_free(m);
	return false;
}

/* ---- builder ------------------------------------------------------------- */

static bool wb_reserve(struct wire_buf *w, size_t n)
{
	size_t need = w->len + n;

	if (need > DNS_MAX_MSG)
		return false;

	if (need > w->size) {
		size_t size = w->size ? w->size : 512;
		uint8_t *buf;

		while (size < need)
			size *= 2;

		if (size > DNS_MAX_MSG)
			size = DNS_MAX_MSG;

		buf = realloc(w->buf, size);
		if (!buf)
			return false;

		w->buf = buf;
		w->size = size;
	}

	return true;
}

static void wb_u16(struct wire_buf *w, uint16_t v)
{
	w->buf[w->len++] = v >> 8;
	w->buf[w->len++] = v & 0xff;
}

static void wb_u32(struct wire_buf *w, uint32_t v)
{
	wb_u16(w, v >> 16);
	wb_u16(w, v & 0xffff);
}

static void wb_set_u16(struct wire_buf *w, size_t pos, uint16_t v)
{
	w->buf[pos] = v >> 8;
	w->buf[pos + 1] = v & 0xff;
}

static uint16_t wb_get_u16(struct wire_buf *w, size_t pos)
{
	return (w->buf[pos] << 8) | w->buf[pos + 1];
}

bool wire_init(struct wire_buf *w, size_t limit)
{
	memset(w, 0, sizeof(*w));
	w->limit = limit ? limit : DNS_MAX_UDP;
	return wb_reserve(w, DNS_HDR_LEN);
}

void wire_free(struct wire_buf *w)
{
	free(w->buf);
	w->buf = NULL;
}

bool wire_put_header(struct wire_buf *w, uint16_t id, uint16_t flags)
{
	w->len = 0;
	w->n_comp = 0;
	w->truncated = false;

	if (!wb_reserve(w, DNS_HDR_LEN))
		return false;

	wb_u16(w, id);
	wb_u16(w, flags);
	wb_u16(w, 0);
	wb_u16(w, 0);
	wb_u16(w, 0);
	wb_u16(w, 0);

	return true;
}

/* Length of the name at offset off in the output buffer, following pointers. */
static bool wb_name_equal_suffix(struct wire_buf *w, size_t off,
				 const uint8_t *name)
{
	unsigned int hops = 0;

	while (true) {
		uint8_t l = w->buf[off];

		if ((l & 0xc0) == 0xc0) {
			if (++hops > 64)
				return false;
			off = ((l & 0x3f) << 8) | w->buf[off + 1];
			continue;
		}

		if (l != *name)
			return false;

		if (!l)
			return true;

		for (unsigned int i = 1; i <= l; i++)
			if (tolower(w->buf[off + i]) != tolower(name[i]))
				return false;

		off += l + 1;
		name += l + 1;
	}
}

/* Write a name, compressing against previously written names. */
static bool wb_name(struct wire_buf *w, const uint8_t *name, bool compress)
{
	const uint8_t *p = name;
	/*
	 * Only names written before this one: the labels of this name are not
	 * terminated yet, matching against them would read past the end.
	 */
	unsigned int n_comp = w->n_comp;

	while (*p) {
		if (compress) {
			for (unsigned int i = 0; i < n_comp; i++) {
				if (!wb_name_equal_suffix(w, w->comp[i], p))
					continue;

				if (!wb_reserve(w, 2))
					return false;
				wb_u16(w, 0xc000 | w->comp[i]);
				return true;
			}
		}

		if (!wb_reserve(w, *p + 1))
			return false;

		if (compress && w->len < 0x3fff &&
		    w->n_comp < sizeof(w->comp) / sizeof(w->comp[0]))
			w->comp[w->n_comp++] = w->len;

		memcpy(w->buf + w->len, p, *p + 1);
		w->len += *p + 1;
		p += *p + 1;
	}

	if (!wb_reserve(w, 1))
		return false;
	w->buf[w->len++] = 0;

	return true;
}

bool wire_put_question(struct wire_buf *w, const uint8_t *qname, uint16_t qtype,
		       uint16_t qclass)
{
	if (!wb_name(w, qname, true) || !wb_reserve(w, 4))
		return false;

	wb_u16(w, qtype);
	wb_u16(w, qclass);
	wb_set_u16(w, 4, wb_get_u16(w, 4) + 1);

	return true;
}

/* Write RDATA, compressing names only for the types RFC 3597 allows. */
static bool wb_rdata(struct wire_buf *w, const struct dns_rr *rr)
{
	const uint8_t *p = rr->rdata;
	bool compress;

	switch (rr->type) {
	case DNS_T_NS:
	case DNS_T_CNAME:
	case DNS_T_PTR:
	case DNS_T_SOA:
	case DNS_T_MX:
		compress = true;
		break;
	default:
		compress = false;
		break;
	}

	if (!compress) {
		if (!wb_reserve(w, rr->rdlen))
			return false;
		memcpy(w->buf + w->len, rr->rdata, rr->rdlen);
		w->len += rr->rdlen;
		return true;
	}

	switch (rr->type) {
	case DNS_T_MX:
		if (!wb_reserve(w, 2))
			return false;
		memcpy(w->buf + w->len, p, 2);
		w->len += 2;
		return wb_name(w, p + 2, true);
	case DNS_T_SOA:
		if (!wb_name(w, p, true))
			return false;
		p += dname_len(p);
		if (!wb_name(w, p, true))
			return false;
		p += dname_len(p);
		if (!wb_reserve(w, 20))
			return false;
		memcpy(w->buf + w->len, p, 20);
		w->len += 20;
		return true;
	default:
		return wb_name(w, p, true);
	}
}

bool wire_put_rr(struct wire_buf *w, int section, const struct dns_rr *rr,
		 uint32_t ttl)
{
	size_t start = w->len, rdpos;
	unsigned int n_comp = w->n_comp;

	if (w->truncated)
		return false;

	if (!wb_name(w, rr->name, true) || !wb_reserve(w, 10))
		goto overflow;

	wb_u16(w, rr->type);
	wb_u16(w, rr->class);
	wb_u32(w, ttl);
	rdpos = w->len;
	wb_u16(w, 0);

	if (!wb_rdata(w, rr))
		goto overflow;

	wb_set_u16(w, rdpos, w->len - rdpos - 2);

	if (w->len + w->opt_reserve > w->limit)
		goto overflow;

	wb_set_u16(w, 6 + 2 * section, wb_get_u16(w, 6 + 2 * section) + 1);
	return true;

overflow:
	/* roll back the partial record */
	w->len = start;
	w->n_comp = n_comp;
	if (section != WIRE_AR) {
		w->truncated = true;
		wire_set_flags(w, DNS_F_TC, 0);
	}
	return false;
}

bool wire_put_opt(struct wire_buf *w, uint16_t udp_size, uint8_t ext_rcode,
		  bool do_bit, int ede, const char *ede_text,
		  const uint8_t *mac, size_t mac_len, uint16_t mac_code,
		  size_t pad_block)
{
	size_t rdpos, start = w->len;
	size_t tlen = ede_text ? strlen(ede_text) : 0;

	if (!wb_reserve(w, 11))
		return false;

	w->buf[w->len++] = 0; /* root name */
	wb_u16(w, DNS_T_OPT);
	wb_u16(w, udp_size);
	wb_u32(w, ((uint32_t)ext_rcode << 24) | (do_bit ? EDNS_DO : 0));
	rdpos = w->len;
	wb_u16(w, 0);

	if (ede >= 0) {
		if (!wb_reserve(w, 6 + tlen))
			goto error;
		wb_u16(w, EDNS_OPT_EDE);
		wb_u16(w, 2 + tlen);
		wb_u16(w, ede);
		if (tlen)
			memcpy(w->buf + w->len, ede_text, tlen);
		w->len += tlen;
	}

	if (mac && mac_len) {
		if (!wb_reserve(w, 4 + mac_len))
			goto error;
		wb_u16(w, mac_code);
		wb_u16(w, mac_len);
		memcpy(w->buf + w->len, mac, mac_len);
		w->len += mac_len;
	}

	if (pad_block) {
		/* RFC 8467: pad the whole message to a multiple of pad_block */
		size_t total = w->len + 4;
		size_t pad = (pad_block - total % pad_block) % pad_block;

		if (!wb_reserve(w, 4 + pad))
			goto error;
		wb_u16(w, EDNS_OPT_PADDING);
		wb_u16(w, pad);
		memset(w->buf + w->len, 0, pad);
		w->len += pad;
	}

	wb_set_u16(w, rdpos, w->len - rdpos - 2);
	wb_set_u16(w, 10, wb_get_u16(w, 10) + 1);
	return true;

error:
	w->len = start;
	return false;
}

void wire_set_rcode(struct wire_buf *w, unsigned int rcode)
{
	uint16_t flags = wb_get_u16(w, 2);

	flags = (flags & ~DNS_F_RCODE_MASK) | (rcode & DNS_F_RCODE_MASK);
	wb_set_u16(w, 2, flags);
}

void wire_set_flags(struct wire_buf *w, uint16_t set, uint16_t clear)
{
	uint16_t flags = wb_get_u16(w, 2);

	wb_set_u16(w, 2, (flags & ~clear) | set);
}
