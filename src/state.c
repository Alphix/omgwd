// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "omgwd.h"

#define STATE_MAX_RECORDS 4096

struct rec_key {
	uint16_t len;
	uint8_t data[];
};

static struct avl_tree records;
static size_t n_records;
static struct uloop_timeout sweep_timer;
static bool warned_full;

static int key_cmp(const void *a, const void *b, void *ptr)
{
	const struct rec_key *ka = a, *kb = b;

	if (ka->len != kb->len)
		return ka->len < kb->len ? -1 : 1;
	return memcmp(ka->data, kb->data, ka->len);
}

/* origin '\0' lowercase-name type rdata */
static struct rec_key *make_key(const char *origin, const struct dns_rr *rr)
{
	size_t ol = strlen(origin) + 1, nl = dname_len(rr->name);
	struct rec_key *k = malloc(sizeof(*k) + ol + nl + 2 + rr->rdlen);
	uint8_t *p;

	if (!k)
		return NULL;
	k->len = ol + nl + 2 + rr->rdlen;
	p = k->data;
	memcpy(p, origin, ol);
	p += ol;
	memcpy(p, rr->name, nl);
	dname_lower(p);
	p += nl;
	*p++ = rr->type >> 8;
	*p++ = rr->type & 0xff;
	if (rr->rdlen)
		memcpy(p, rr->rdata, rr->rdlen);
	return k;
}

static void rec_free(struct state_rec *r)
{
	avl_delete(&records, &r->avl);
	n_records--;
	free(r->key);
	free(r->rr.rdata);
	free(r);
}

/* drop what has expired (the fuzz harness calls this directly) */
void state_expire(void)
{
	int64_t now = now_ms();
	struct state_rec *r, *tmp;

	avl_for_each_element_safe(&records, r, avl, tmp) if (r->expires <= now)
		rec_free(r);

	xlat_state_changed();
}

static void sweep_cb(struct uloop_timeout *t)
{
	state_expire();
	if (n_records)
		uloop_timeout_set(&sweep_timer, 1000);
}

void state_init(void)
{
	avl_init(&records, key_cmp, false, NULL);
	sweep_timer.cb = sweep_cb;
}

static void cache_flush(const char *origin, const struct dns_rr *rr,
			int64_t now)
{
	struct state_rec *r;

	avl_for_each_element(&records, r, avl)
	{
		if (r->rr.type != rr->type || strcmp(r->origin, origin) ||
		    !dname_equal(r->rr.name, rr->name))
			continue;
		if (r->rr.rdlen == rr->rdlen &&
		    (!rr->rdlen || !memcmp(r->rr.rdata, rr->rdata, rr->rdlen)))
			continue;
		if (r->seen < now - 1000 && r->expires > now + 1000)
			r->expires = now + 1000;
	}
}

static void update_rr(struct iface *in, int family, const struct dns_rr *rr,
		      int64_t now)
{
	struct state_rec *r;
	struct rec_key *k;

	if (rr->type == DNS_T_OPT)
		return;
	if (rr->class & 0x8000)
		cache_flush(in->name, rr, now);

	k = make_key(in->name, rr);
	if (!k)
		return;

	r = avl_find_element(&records, k, r, avl);
	if (r) {
		free(k);
	} else {
		if (n_records >= STATE_MAX_RECORDS) {
			if (!warned_full)
				log_warn(
					"state full (%d records), ignoring new records",
					STATE_MAX_RECORDS);
			warned_full = true;
			free(k);
			return;
		}
		r = calloc(1, sizeof(*r));
		if (!r) {
			free(k);
			return;
		}
		r->key = k;
		r->avl.key = k;
		snprintf(r->origin, sizeof(r->origin), "%s", in->name);
		r->rr = *rr;
		r->rr.rdata = NULL;
		if (rr->rdlen) {
			r->rr.rdata = malloc(rr->rdlen);
			if (!r->rr.rdata) {
				free(k);
				free(r);
				return;
			}
			memcpy(r->rr.rdata, rr->rdata, rr->rdlen);
		}
		avl_insert(&records, &r->avl);
		n_records++;
	}

	r->rr.class = rr->class;
	r->rr.ttl = rr->ttl;
	r->families |= family == AF_INET ? STATE_V4 : STATE_V6;
	r->seen = now;
	/* goodbye: keep for a second (RFC 6762 10.1) */
	r->expires = now + (rr->ttl ? (int64_t)rr->ttl * 1000 : 1000);
}

void state_update(struct iface *in, int family, const struct dns_msg *m)
{
	int64_t now = now_ms();

	if (!(m->flags & DNS_F_QR))
		return;

	for (size_t i = 0; i < m->an.n; i++)
		update_rr(in, family, &m->an.rr[i], now);
	for (size_t i = 0; i < m->ns.n; i++)
		update_rr(in, family, &m->ns.rr[i], now);
	for (size_t i = 0; i < m->ar.n; i++)
		update_rr(in, family, &m->ar.rr[i], now);

	if (n_records && !sweep_timer.pending)
		uloop_timeout_set(&sweep_timer, 1000);
}

/*
 * Names for humans (ubus, LuCI): mDNS instance names are UTF-8 text with
 * spaces, so only '.' and '\\' inside a label are escaped, unlike the zone
 * file presentation format of dname_to_str().
 */
void dname_to_display(const uint8_t *name, char *buf, size_t len)
{
	size_t o = 0;

	if (!len)
		return;
	while (*name && o + 1 < len) {
		uint8_t l = *name++;

		if (o && o + 1 < len)
			buf[o++] = '.';
		for (uint8_t k = 0; k < l && o + 2 < len; k++) {
			char c = name[k];

			if (c == '.' || c == '\\')
				buf[o++] = '\\';
			buf[o++] = c;
		}
		name += l;
	}
	buf[o] = '\0';
}

/* ---- queries ----------------------------------------------------------------- */

struct state_rec *state_first(void)
{
	return avl_is_empty(&records) ?
		       NULL :
		       avl_first_element(&records, (struct state_rec *)NULL,
					 avl);
}

struct state_rec *state_next(struct state_rec *r)
{
	if (r == avl_last_element(&records, r, avl))
		return NULL;
	return avl_next_element(r, avl);
}

static bool usable_aaaa(const struct state_rec *r)
{
	const struct in6_addr *a = (const struct in6_addr *)r->rr.rdata;

	if (r->rr.type != DNS_T_AAAA || r->rr.rdlen != 16 ||
	    !(r->families & STATE_V6))
		return false;
	if (IN6_IS_ADDR_LINKLOCAL(a) || IN6_IS_ADDR_UNSPECIFIED(a) ||
	    IN6_IS_ADDR_LOOPBACK(a))
		return false;
	/* a stand-in, e.g. advertised by another gateway: not native */
	return !iface_addr_is_standin(a);
}

/* SRV target of an instance (from any network), or NULL */
const uint8_t *state_srv_target(const uint8_t *instance, uint8_t *families)
{
	struct state_rec *r;

	for (r = state_first(); r; r = state_next(r))
		if (r->rr.type == DNS_T_SRV && r->rr.rdlen > 6 &&
		    dname_equal(r->rr.name, instance)) {
			if (families)
				*families = r->families;
			return r->rr.rdata + 6;
		}
	return NULL;
}

/* does the device on origin announce AAAA records of its own for host (any family)? */
bool state_host_has_aaaa(const char *origin, const uint8_t *host)
{
	struct state_rec *r;

	for (r = state_first(); r; r = state_next(r))
		if (r->rr.type == DNS_T_AAAA && r->rr.rdlen == 16 &&
		    r->rr.ttl && !strcmp(r->origin, origin) &&
		    dname_equal(r->rr.name, host) &&
		    !iface_addr_is_standin(
			    (const struct in6_addr *)r->rr.rdata))
			return true;
	return false;
}

/* answered over IPv6 with a usable (non link-local, non stand-in) address */
bool state_instance_native_v6(const uint8_t *instance)
{
	uint8_t fam = 0;
	const uint8_t *host = state_srv_target(instance, &fam);
	struct state_rec *r;

	if (!host || !(fam & STATE_V6))
		return false;
	for (r = state_first(); r; r = state_next(r))
		if (usable_aaaa(r) && dname_equal(r->rr.name, host))
			return true;
	return false;
}

/*
 * Record data for humans: names in PTR and SRV in the display format (an
 * instance name like "Test TV" stays readable, see dname_to_display()), TXT
 * as its strings ("fn=Tv"; quoted when empty or containing a space, other
 * unprintable bytes as \DDD). Everything else in the zone file format.
 */
static int display_rdata(const struct dns_rr *rr, char *buf, size_t len)
{
	const uint8_t *d = rr->rdata;
	size_t o = 0;

	switch (rr->type) {
	case DNS_T_PTR:
		if (!rr->rdlen || dname_len(d) > rr->rdlen)
			break;
		dname_to_display(d, buf, len);
		return 0;
	case DNS_T_SRV:
		if (rr->rdlen < 7 || dname_len(d + 6) > rr->rdlen - 6U)
			break;
		o = snprintf(buf, len, "%u %u %u ", d[0] << 8 | d[1],
			     d[2] << 8 | d[3], d[4] << 8 | d[5]);
		if (o >= len)
			break;
		dname_to_display(d + 6, buf + o, len - o);
		return 0;
	case DNS_T_TXT:
		for (size_t i = 0; i < rr->rdlen;) {
			size_t n = d[i++];
			bool quote =
				!n ||
				memchr(d + i, ' ',
				       n < rr->rdlen - i ? n : rr->rdlen - i);

			if (i + n > rr->rdlen)
				goto generic;
			if (o + 4 * n + 4 >= len)
				goto generic;
			if (o)
				buf[o++] = ' ';
			if (quote)
				buf[o++] = '"';
			for (size_t k = 0; k < n; k++, i++) {
				uint8_t c = d[i];

				if (c < 0x20 || c == 0x7f || c == '"' ||
				    c == '\\')
					o += sprintf(buf + o, "\\%03u", c);
				else
					buf[o++] = c;
			}
			if (quote)
				buf[o++] = '"';
		}
		buf[o] = '\0';
		return 0;
	default:
		break;
	}
generic:
	return rr_rdata_to_str(rr->type, rr->rdata, rr->rdlen, buf, len) < 0 ?
		       -1 :
		       0;
}

void state_dump_records(struct blob_buf *b)
{
	void *a = blobmsg_open_array(b, "records");
	int64_t now = now_ms();
	struct state_rec *r;

	for (r = state_first(); r; r = state_next(r)) {
		char name[DNAME_STR_MAX], type[16], rdata[512];
		void *t = blobmsg_open_table(b, NULL);

		dname_to_display(r->rr.name, name, sizeof(name));
		blobmsg_add_string(b, "network", r->origin);
		blobmsg_add_string(b, "name", name);
		blobmsg_add_string(b, "type",
				   rr_type_name(r->rr.type, type,
						sizeof(type)));
		if (!display_rdata(&r->rr, rdata, sizeof(rdata)))
			blobmsg_add_string(b, "data", rdata);
		blobmsg_add_u8(b, "ipv4", !!(r->families & STATE_V4));
		blobmsg_add_u8(b, "ipv6", !!(r->families & STATE_V6));
		blobmsg_add_u32(
			b, "expires",
			r->expires > now ? (r->expires - now + 999) / 1000 : 0);
		blobmsg_close_table(b, t);
	}
	blobmsg_close_array(b, a);
}
