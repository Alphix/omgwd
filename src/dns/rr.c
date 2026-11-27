// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "dns.h"

void rr_list_init(struct rr_list *l)
{
	memset(l, 0, sizeof(*l));
}

void rr_list_free(struct rr_list *l)
{
	for (size_t i = 0; i < l->n; i++)
		free(l->rr[i].rdata);

	free(l->rr);
	rr_list_init(l);
}

struct dns_rr *rr_list_add(struct rr_list *l, const uint8_t *name,
			   uint16_t type, uint16_t class, uint32_t ttl,
			   const void *rdata, uint16_t rdlen)
{
	struct dns_rr *rr;

	if (l->n == l->alloc) {
		size_t alloc = l->alloc ? l->alloc * 2 : 4;
		struct dns_rr *n = realloc(l->rr, alloc * sizeof(*n));

		if (!n)
			return NULL;

		l->rr = n;
		l->alloc = alloc;
	}

	rr = &l->rr[l->n];
	memset(rr, 0, sizeof(*rr));
	dname_copy(rr->name, name);
	rr->type = type;
	rr->class = class;
	rr->ttl = ttl;

	if (rdata) {
		rr->rdata = malloc(rdlen ? rdlen : 1);
		if (!rr->rdata)
			return NULL;
		memcpy(rr->rdata, rdata, rdlen);
		rr->rdlen = rdlen;
	}

	l->n++;
	return rr;
}

bool rr_list_append(struct rr_list *dst, const struct rr_list *src)
{
	for (size_t i = 0; i < src->n; i++) {
		const struct dns_rr *rr = &src->rr[i];

		if (!rr_list_add(dst, rr->name, rr->type, rr->class, rr->ttl,
				 rr->rdata, rr->rdlen))
			return false;
	}

	return true;
}

static const struct {
	uint16_t type;
	const char *name;
} rr_types[] = {
	{ DNS_T_A, "A" },	  { DNS_T_NS, "NS" },
	{ DNS_T_MD, "MD" },	  { DNS_T_MF, "MF" },
	{ DNS_T_CNAME, "CNAME" }, { DNS_T_SOA, "SOA" },
	{ DNS_T_MB, "MB" },	  { DNS_T_MG, "MG" },
	{ DNS_T_MR, "MR" },	  { DNS_T_PTR, "PTR" },
	{ DNS_T_HINFO, "HINFO" }, { DNS_T_MINFO, "MINFO" },
	{ DNS_T_MX, "MX" },	  { DNS_T_TXT, "TXT" },
	{ DNS_T_RP, "RP" },	  { DNS_T_AFSDB, "AFSDB" },
	{ DNS_T_RT, "RT" },	  { DNS_T_PX, "PX" },
	{ DNS_T_AAAA, "AAAA" },	  { DNS_T_SRV, "SRV" },
	{ DNS_T_NAPTR, "NAPTR" }, { DNS_T_KX, "KX" },
	{ DNS_T_A6, "A6" },	  { DNS_T_DNAME, "DNAME" },
	{ DNS_T_OPT, "OPT" },	  { DNS_T_DS, "DS" },
	{ DNS_T_SSHFP, "SSHFP" }, { DNS_T_RRSIG, "RRSIG" },
	{ DNS_T_NSEC, "NSEC" },	  { DNS_T_DNSKEY, "DNSKEY" },
	{ DNS_T_NSEC3, "NSEC3" }, { DNS_T_NSEC3PARAM, "NSEC3PARAM" },
	{ DNS_T_TLSA, "TLSA" },	  { DNS_T_SVCB, "SVCB" },
	{ DNS_T_HTTPS, "HTTPS" }, { DNS_T_ANY, "ANY" },
	{ DNS_T_CAA, "CAA" },
};

const char *rr_type_name(uint16_t type, char *buf, size_t len)
{
	for (size_t i = 0; i < sizeof(rr_types) / sizeof(rr_types[0]); i++)
		if (rr_types[i].type == type)
			return rr_types[i].name;

	snprintf(buf, len, "TYPE%u", type);
	return buf;
}

int rr_type_from_name(const char *name)
{
	char *end;
	unsigned long v;

	for (size_t i = 0; i < sizeof(rr_types) / sizeof(rr_types[0]); i++)
		if (!strcasecmp(rr_types[i].name, name))
			return rr_types[i].type;

	if (strncasecmp(name, "TYPE", 4))
		return -1;

	v = strtoul(name + 4, &end, 10);
	if (*end || end == name + 4 || !v || v > 65535)
		return -1;

	return v;
}

/*
 * Types whose RDATA contains names that may arrive compressed: the RFC 1035
 * types, plus the ones RFC 3597 4 says receivers should decompress.
 */
bool rr_type_has_names(uint16_t type)
{
	switch (type) {
	case DNS_T_NS:
	case DNS_T_MD:
	case DNS_T_MF:
	case DNS_T_CNAME:
	case DNS_T_SOA:
	case DNS_T_MB:
	case DNS_T_MG:
	case DNS_T_MR:
	case DNS_T_PTR:
	case DNS_T_MINFO:
	case DNS_T_MX:
	case DNS_T_RP:
	case DNS_T_AFSDB:
	case DNS_T_RT:
	case DNS_T_PX:
	case DNS_T_SRV:
	case DNS_T_NAPTR:
	case DNS_T_KX:
	case DNS_T_A6:
	case DNS_T_DNAME:
		return true;
	default:
		return false;
	}
}

/* ---- presentation format ------------------------------------------------ */

struct tok {
	const char *p;
};

/* next whitespace separated token; quoted strings may contain spaces */
static int next_token(struct tok *t, char *buf, size_t len, bool *quoted)
{
	size_t o = 0;

	while (isspace((unsigned char)*t->p))
		t->p++;

	if (!*t->p)
		return -1;

	*quoted = false;
	if (*t->p == '"') {
		*quoted = true;
		t->p++;
		while (*t->p && *t->p != '"') {
			if (*t->p == '\\' && t->p[1])
				t->p++;
			if (o + 1 >= len)
				return -1;
			buf[o++] = *t->p++;
		}
		if (*t->p != '"')
			return -1;
		t->p++;
	} else {
		while (*t->p && !isspace((unsigned char)*t->p)) {
			if (o + 1 >= len)
				return -1;
			buf[o++] = *t->p++;
		}
	}

	buf[o] = 0;
	return o;
}

static bool tok_done(struct tok *t)
{
	while (isspace((unsigned char)*t->p))
		t->p++;

	return !*t->p;
}

static bool tok_uint(struct tok *t, unsigned long max, unsigned long *v)
{
	char buf[32], *end;
	bool q;

	if (next_token(t, buf, sizeof(buf), &q) <= 0)
		return false;

	*v = strtoul(buf, &end, 10);
	if (*end || *v > max)
		return false;

	return true;
}

static int tok_name(struct tok *t, uint8_t *out, size_t outlen)
{
	char buf[DNAME_STR_MAX];
	uint8_t name[DNAME_MAX + 1];
	bool q;
	int n;

	if (next_token(t, buf, sizeof(buf), &q) <= 0)
		return -1;

	n = dname_from_str(name, buf);
	if (n < 0 || (size_t)n > outlen)
		return -1;

	memcpy(out, name, n);
	return n;
}

static int tok_hex(struct tok *t, uint8_t *out, size_t outlen)
{
	char buf[4096];
	size_t o = 0;
	bool q;

	/* hex may be split over several tokens */
	while (!tok_done(t)) {
		int n = next_token(t, buf, sizeof(buf), &q);

		if (n < 0 || n % 2)
			return -1;

		for (int i = 0; i < n; i += 2) {
			unsigned int v;

			if (o >= outlen || !isxdigit((unsigned char)buf[i]) ||
			    !isxdigit((unsigned char)buf[i + 1]) ||
			    sscanf(buf + i, "%2x", &v) != 1)
				return -1;
			out[o++] = v;
		}
	}

	return o;
}

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

/*
 * RDATA given in the generic form for a type with embedded names: the names
 * must be complete and uncompressed, as everything else handling RDATA of
 * these types (builder, presentation output) relies on that. Checked by
 * parsing it the way an upstream response would be.
 */
static bool generic_names_valid(uint16_t type, const uint8_t *rdata, size_t len)
{
	uint8_t msg[DNS_HDR_LEN + 11 + 4096];
	struct dns_msg m;
	bool ok;

	if (len > 4096)
		return false;

	memset(msg, 0, DNS_HDR_LEN + 1);
	msg[7] = 1; /* one answer, root owner */
	put16(msg + DNS_HDR_LEN + 1, type);
	put16(msg + DNS_HDR_LEN + 3, DNS_C_IN);
	memset(msg + DNS_HDR_LEN + 5, 0, 4); /* TTL */
	put16(msg + DNS_HDR_LEN + 9, len);
	memcpy(msg + DNS_HDR_LEN + 11, rdata, len);

	if (!wire_parse(msg, DNS_HDR_LEN + 11 + len, &m, false))
		return false;

	/* nothing was compressed: the parsed RDATA is the input */
	ok = m.an.n == 1 && m.an.rr[0].rdlen == len &&
	     !memcmp(m.an.rr[0].rdata, rdata, len);
	dns_msg_free(&m);
	return ok;
}

/*
 * Parse RDATA in presentation format for well-known types, or the RFC 3597
 * generic form "\# <len> <hex>" for any type. Returns the RDATA length.
 */
int rr_rdata_from_str(uint16_t type, const char *str, uint8_t *out,
		      size_t outlen)
{
	struct tok t = { .p = str };
	char buf[1024];
	unsigned long v, v2, v3;
	bool q;
	int n, o = 0;

	/* OPT and the query/meta types (RFC 6895 3.1) are no data */
	if (type == DNS_T_OPT || (type >= 128 && type <= 255))
		return -1;

	while (isspace((unsigned char)*t.p))
		t.p++;

	if (!strncmp(t.p, "\\#", 2) &&
	    (isspace((unsigned char)t.p[2]) || !t.p[2])) {
		t.p += 2;
		if (!tok_uint(&t, 65535, &v))
			return -1;
		n = tok_hex(&t, out, outlen);
		if (n < 0 || (unsigned long)n != v)
			return -1;
		if (rr_type_has_names(type) &&
		    !generic_names_valid(type, out, n))
			return -1;
		return n;
	}

	switch (type) {
	case DNS_T_A:
		if (outlen < 4 || next_token(&t, buf, sizeof(buf), &q) <= 0 ||
		    inet_pton(AF_INET, buf, out) != 1)
			return -1;
		o = 4;
		break;
	case DNS_T_AAAA:
		if (outlen < 16 || next_token(&t, buf, sizeof(buf), &q) <= 0 ||
		    inet_pton(AF_INET6, buf, out) != 1)
			return -1;
		o = 16;
		break;
	case DNS_T_NS:
	case DNS_T_CNAME:
	case DNS_T_DNAME:
	case DNS_T_PTR:
		o = tok_name(&t, out, outlen);
		break;
	case DNS_T_MX:
		if (outlen < 2 || !tok_uint(&t, 65535, &v))
			return -1;
		put16(out, v);
		n = tok_name(&t, out + 2, outlen - 2);
		o = n < 0 ? -1 : n + 2;
		break;
	case DNS_T_SRV:
		if (outlen < 6 || !tok_uint(&t, 65535, &v) ||
		    !tok_uint(&t, 65535, &v2) || !tok_uint(&t, 65535, &v3))
			return -1;
		put16(out, v);
		put16(out + 2, v2);
		put16(out + 4, v3);
		n = tok_name(&t, out + 6, outlen - 6);
		o = n < 0 ? -1 : n + 6;
		break;
	case DNS_T_TXT:
		while (!tok_done(&t)) {
			n = next_token(&t, buf, sizeof(buf), &q);
			if (n < 0 || n > 255 || o + 1 + n > (int)outlen)
				return -1;
			out[o++] = n;
			memcpy(out + o, buf, n);
			o += n;
		}
		if (!o)
			return -1;
		return o;
	case DNS_T_CAA:
		if (!tok_uint(&t, 255, &v))
			return -1;
		n = next_token(&t, buf, sizeof(buf), &q);
		if (n <= 0 || n > 255 || 2 + n > (int)outlen)
			return -1;
		out[0] = v;
		out[1] = n;
		memcpy(out + 2, buf, n);
		o = 2 + n;
		n = next_token(&t, buf, sizeof(buf), &q);
		if (n < 0 || o + n > (int)outlen)
			return -1;
		memcpy(out + o, buf, n);
		o += n;
		break;
	case DNS_T_SSHFP:
		if (outlen < 2 || !tok_uint(&t, 255, &v) ||
		    !tok_uint(&t, 255, &v2))
			return -1;
		out[0] = v;
		out[1] = v2;
		n = tok_hex(&t, out + 2, outlen - 2);
		return n <= 0 ? -1 : n + 2;
	case DNS_T_DS:
		/* key tag, algorithm, digest type, digest (hex) */
		if (outlen < 4 || !tok_uint(&t, 65535, &v) ||
		    !tok_uint(&t, 255, &v2) || !tok_uint(&t, 255, &v3))
			return -1;
		put16(out, v);
		out[2] = v2;
		out[3] = v3;
		n = tok_hex(&t, out + 4, outlen - 4);
		return n <= 0 ? -1 : n + 4;
	case DNS_T_TLSA:
		if (outlen < 3 || !tok_uint(&t, 255, &v) ||
		    !tok_uint(&t, 255, &v2) || !tok_uint(&t, 255, &v3))
			return -1;
		out[0] = v;
		out[1] = v2;
		out[2] = v3;
		n = tok_hex(&t, out + 3, outlen - 3);
		return n <= 0 ? -1 : n + 3;
	default:
		/* TODO: SVCB/HTTPS, NAPTR, SOA, ... presentation formats */
		return -1;
	}

	if (o < 0 || !tok_done(&t))
		return -1;

	return o;
}

int rr_rdata_to_str(uint16_t type, const uint8_t *rdata, uint16_t rdlen,
		    char *buf, size_t len)
{
	char name[DNAME_STR_MAX];
	size_t o = 0;

	switch (type) {
	case DNS_T_A:
		if (rdlen == 4 && inet_ntop(AF_INET, rdata, buf, len))
			return strlen(buf);
		break;
	case DNS_T_AAAA:
		if (rdlen == 16 && inet_ntop(AF_INET6, rdata, buf, len))
			return strlen(buf);
		break;
	case DNS_T_NS:
	case DNS_T_CNAME:
	case DNS_T_DNAME:
	case DNS_T_PTR:
		if (dname_to_str(rdata, name, sizeof(name)) < 0)
			break;
		return snprintf(buf, len, "%s.", name);
	case DNS_T_MX:
		if (rdlen < 3 ||
		    dname_to_str(rdata + 2, name, sizeof(name)) < 0)
			break;
		return snprintf(buf, len, "%u %s.", (rdata[0] << 8) | rdata[1],
				name);
	case DNS_T_SRV:
		if (rdlen < 7 ||
		    dname_to_str(rdata + 6, name, sizeof(name)) < 0)
			break;
		return snprintf(buf, len, "%u %u %u %s.",
				(rdata[0] << 8) | rdata[1],
				(rdata[2] << 8) | rdata[3],
				(rdata[4] << 8) | rdata[5], name);
	default:
		break;
	}

	/* RFC 3597 generic form */
	o = snprintf(buf, len, "\\# %u", rdlen);
	if (rdlen && o + 1 < len)
		buf[o++] = ' ';
	for (unsigned int i = 0; i < rdlen && o + 3 < len; i++)
		o += snprintf(buf + o, len - o, "%02x", rdata[i]);

	return o;
}

/*
 * Iterate the ipv4hint (4) and ipv6hint (6) SvcParams of SVCB/HTTPS RDATA:
 * priority(2) target(name) { key(2) len(2) value }*. Stops when cb returns
 * true; returns that result.
 */
bool rr_svcb_for_each_hint(const uint8_t *rdata, uint16_t rdlen, rr_addr_cb cb,
			   void *priv)
{
	size_t pos = 2;

	if (rdlen < 3)
		return false;

	/* target name is never compressed */
	while (pos < rdlen && rdata[pos]) {
		pos += rdata[pos] + 1;
	}
	pos++;

	while (pos + 4 <= rdlen) {
		uint16_t key = (rdata[pos] << 8) | rdata[pos + 1];
		uint16_t len = (rdata[pos + 2] << 8) | rdata[pos + 3];

		pos += 4;
		if (pos + len > rdlen)
			return false;

		if (key == 4) {
			for (size_t i = 0; i + 4 <= len; i += 4)
				if (cb(AF_INET, rdata + pos + i, priv))
					return true;
		} else if (key == 6) {
			for (size_t i = 0; i + 16 <= len; i += 16)
				if (cb(AF_INET6, rdata + pos + i, priv))
					return true;
		}

		pos += len;
	}

	return false;
}
