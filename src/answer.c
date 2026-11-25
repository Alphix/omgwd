// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <stdlib.h>
#include <string.h>

#include "omgwd.h"

#define MAX_OUT 64

struct out_rr {
	struct dns_rr rr;
	uint8_t rdata[DNAME_MAX +
		      64]; /* own copy: stand-ins, and survives the state */
	int section;
};

struct answer {
	struct iface *a, *b;
	const struct dns_msg *q;
	struct out_rr out[MAX_OUT];
	size_t n;
	int64_t now;
};

static uint8_t enum_name[DNAME_MAX + 1];

/* ---- RFC 6762 section 6: one multicast per record per second ---------------- */

#define SENT_SLOTS 256

static struct {
	int ifindex;
	uint64_t hash;
	int64_t when;
} sent[SENT_SLOTS];
static unsigned int sent_next;

static uint64_t rr_hash(const struct dns_rr *rr)
{
	uint64_t h = dname_hash(rr->name) ^ ((uint64_t)rr->type << 48);

	for (size_t i = 0; i < rr->rdlen; i++) {
		h ^= rr->rdata[i];
		h *= 0x100000001b3ULL;
	}
	return h;
}

static bool sent_within(const struct iface *b, uint64_t h, int64_t now)
{
	for (size_t i = 0; i < SENT_SLOTS; i++)
		if (sent[i].ifindex == b->ifindex && sent[i].hash == h &&
		    now - sent[i].when < 1000)
			return true;
	return false;
}

static void sent_note(const struct iface *b, uint64_t h, int64_t now)
{
	sent[sent_next].ifindex = b->ifindex;
	sent[sent_next].hash = h;
	sent[sent_next].when = now;
	sent_next = (sent_next + 1) % SENT_SLOTS;
}

/*
 * For translated responses (xlat.c): true = leave this record out, it was
 * multicast on b within the last second. Otherwise it's noted as sent.
 * Goodbyes always go out.
 */
bool answer_suppress(const struct iface *b, const struct dns_rr *rr)
{
	int64_t now = now_ms();
	uint64_t h;

	if (!config.answer_from_state || !rr->ttl)
		return false;
	h = rr_hash(rr);
	if (sent_within(b, h, now))
		return true;
	sent_note(b, h, now);
	return false;
}

/* ---- building the answer ------------------------------------------------- */

static uint32_t remaining(const struct state_rec *r, int64_t now)
{
	if (!r->rr.ttl || r->expires <= now)
		return 0;
	return (r->expires - now) / 1000;
}

/* RFC 6762 7.1: the querier already has it with at least half its TTL */
static bool known(const struct answer *ans, const struct dns_rr *rr,
		  uint32_t full_ttl)
{
	const struct rr_list *ka = &ans->q->an;

	for (size_t i = 0; i < ka->n; i++)
		if (ka->rr[i].type == rr->type &&
		    ka->rr[i].rdlen == rr->rdlen &&
		    ka->rr[i].ttl >= full_ttl / 2 &&
		    dname_equal(ka->rr[i].name, rr->name) &&
		    (!rr->rdlen ||
		     !memcmp(ka->rr[i].rdata, rr->rdata, rr->rdlen)))
			return true;
	return false;
}

/* add a record (once; an answer beats an additional) */
static void add(struct answer *ans, int section, const struct dns_rr *rr,
		uint32_t ttl, uint32_t full_ttl)
{
	struct out_rr *o;

	if (!ttl || rr->rdlen > sizeof(o->rdata) || known(ans, rr, full_ttl))
		return;
	for (size_t i = 0; i < ans->n; i++) {
		o = &ans->out[i];
		if (o->rr.type == rr->type && o->rr.rdlen == rr->rdlen &&
		    dname_equal(o->rr.name, rr->name) &&
		    (!rr->rdlen ||
		     !memcmp(o->rr.rdata, rr->rdata, rr->rdlen))) {
			if (section == WIRE_AN)
				o->section = WIRE_AN;
			return;
		}
	}
	if (ans->n >= MAX_OUT)
		return;
	o = &ans->out[ans->n++];
	o->rr = *rr;
	o->rr.ttl = ttl;
	if (rr->rdlen)
		memcpy(o->rdata, rr->rdata, rr->rdlen);
	o->rr.rdata = o->rdata;
	o->section = section;
}

static bool from_a(const struct answer *ans, const struct state_rec *r)
{
	return (r->families & STATE_V4) && !strcmp(r->origin, ans->a->name);
}

/* the host's live A records (and their stand-ins), for this instance */
static bool add_host(struct answer *ans, const uint8_t *instance,
		     const uint8_t *host, int sec_a, int sec_aaaa)
{
	bool any = false;

	for (struct state_rec *r = state_first(); r; r = state_next(r)) {
		uint32_t ttl = remaining(r, ans->now);
		struct in6_addr s6;
		struct dns_rr aaaa;

		if (r->rr.type != DNS_T_A || r->rr.rdlen != 4 ||
		    rr_link_local_addr(&r->rr) || !ttl || !from_a(ans, r) ||
		    !dname_equal(r->rr.name, host))
			continue;
		any = true;
		if (sec_a >= 0)
			add(ans, sec_a, &r->rr, ttl, r->rr.ttl);
		if (sec_aaaa < 0 || !xlat_standin_for(ans->a, ans->b, instance,
						      host, r->rr.rdata, &s6))
			continue;
		aaaa = r->rr;
		aaaa.type = DNS_T_AAAA;
		aaaa.rdlen = 16;
		aaaa.rdata = s6.s6_addr;
		add(ans, sec_aaaa, &aaaa, ttl, r->rr.ttl);
		xlat_note_standin(ans->a, ans->b, instance, host, &s6,
				  r->rr.class, ttl);
	}
	return any;
}

/* host of a translated instance from A with a live A record, or NULL */
static const uint8_t *instance_host(struct answer *ans, const uint8_t *instance)
{
	for (struct state_rec *r = state_first(); r; r = state_next(r)) {
		const uint8_t *host;

		if (r->rr.type != DNS_T_SRV || r->rr.rdlen <= 6 ||
		    !remaining(r, ans->now) || !from_a(ans, r) ||
		    !dname_equal(r->rr.name, instance))
			continue;
		host = r->rr.rdata + 6;
		if (!xlat_decide(ans->a, ans->b, instance, host))
			return NULL;
		for (struct state_rec *h = state_first(); h; h = state_next(h))
			if (h->rr.type == DNS_T_A &&
			    !rr_link_local_addr(&h->rr) &&
			    remaining(h, ans->now) && from_a(ans, h) &&
			    dname_equal(h->rr.name, host))
				return host;
		return NULL;
	}
	return NULL;
}

/* SRV + TXT of an instance (in section sec) and its host's addresses */
static void add_instance(struct answer *ans, const uint8_t *instance,
			 const uint8_t *host, int sec, uint16_t only_type)
{
	for (struct state_rec *r = state_first(); r; r = state_next(r)) {
		uint32_t ttl = remaining(r, ans->now);

		if ((r->rr.type != DNS_T_SRV && r->rr.type != DNS_T_TXT) ||
		    !ttl || !from_a(ans, r) ||
		    !dname_equal(r->rr.name, instance))
			continue;
		add(ans, only_type && r->rr.type != only_type ? WIRE_AR : sec,
		    &r->rr, ttl, r->rr.ttl);
	}
	add_host(ans, instance, host, WIRE_AR, WIRE_AR);
}

static void answer_ptr(struct answer *ans, const uint8_t *name)
{
	bool services = dname_equal(name, enum_name);

	for (struct state_rec *r = state_first(); r; r = state_next(r)) {
		uint32_t ttl = remaining(r, ans->now);
		const uint8_t *host;

		if (r->rr.type != DNS_T_PTR || !r->rr.rdlen || !ttl ||
		    !from_a(ans, r) || !dname_equal(r->rr.name, name) ||
		    !xlat_pair_allows(ans->a, ans->b, r->rr.rdata))
			continue;
		if (services) {
			add(ans, WIRE_AN, &r->rr, ttl, r->rr.ttl);
			continue;
		}
		host = instance_host(ans, r->rr.rdata);
		if (!host)
			continue;
		add(ans, WIRE_AN, &r->rr, ttl, r->rr.ttl);
		add_instance(ans, r->rr.rdata, host, WIRE_AR, 0);
	}
}

static void answer_question(struct answer *ans, const struct dns_question *q)
{
	uint16_t t = q->type;
	const uint8_t *host, *instance;

	if ((q->class & 0x7fff) != DNS_C_IN && (q->class & 0x7fff) != DNS_C_ANY)
		return;

	if (t == DNS_T_PTR || t == DNS_T_ANY)
		answer_ptr(ans, q->name);

	if (t == DNS_T_SRV || t == DNS_T_TXT || t == DNS_T_ANY) {
		host = instance_host(ans, q->name);
		if (host)
			add_instance(ans, q->name, host, WIRE_AN,
				     t == DNS_T_ANY ? 0 : t);
	}

	if (t == DNS_T_A || t == DNS_T_AAAA || t == DNS_T_ANY) {
		instance = xlat_instance_for_host(ans->a, ans->b, q->name);
		if (instance && instance_host(ans, instance))
			add_host(ans, instance, q->name,
				 t == DNS_T_AAAA ? WIRE_AR : WIRE_AN,
				 t == DNS_T_A ? WIRE_AR : WIRE_AN);
	}
}

static void send_answer(struct answer *ans)
{
	struct wire_buf w;
	size_t n_an = 0;
	uint64_t h[MAX_OUT];

	/* RFC 6762 section 6, and the sections in order */
	for (size_t i = 0; i < ans->n; i++) {
		h[i] = rr_hash(&ans->out[i].rr);
		if (sent_within(ans->b, h[i], ans->now))
			ans->out[i].section = -1;
		else if (ans->out[i].section == WIRE_AN)
			n_an++;
	}
	if (!n_an)
		return;

	if (wire_init(&w, 9000) || wire_put_header(&w, 0, DNS_F_QR | DNS_F_AA))
		goto out;
	for (int sec = WIRE_AN; sec <= WIRE_AR; sec++)
		for (size_t i = 0; i < ans->n; i++)
			if (ans->out[i].section == sec &&
			    wire_put_rr(&w, sec, &ans->out[i].rr,
					ans->out[i].rr.ttl) &&
			    sec != WIRE_AR)
				goto out;

	if (!mdns_send(ans->b, AF_INET6, w.buf, w.len)) {
		ans->b->tx_answered++;
		for (size_t i = 0; i < ans->n; i++)
			if (ans->out[i].section >= 0)
				sent_note(ans->b, h[i], ans->now);
	}
out:
	wire_free(&w);
}

void answer_query(struct iface *in, int family, const struct dns_msg *m)
{
	static struct answer ans;
	struct iface *a;

	if (!config.enabled || !config.answer_from_state ||
	    family != AF_INET6 || (m->flags & DNS_F_QR) ||
	    (m->flags & DNS_F_TC) || m->ns.n || !m->n_qd)
		return;
	if (!enum_name[0])
		dname_from_str(enum_name, "_services._dns-sd._udp.local");

	avl_for_each_element(&ifaces, a, avl)
	{
		if (!a->up || !xlat_pair_allows(a, in, NULL))
			continue;
		memset(&ans, 0, sizeof(ans));
		ans.a = a;
		ans.b = in;
		ans.q = m;
		ans.now = now_ms();
		for (size_t i = 0; i < m->n_qd; i++)
			answer_question(&ans, &m->qd[i]);
		if (ans.n)
			send_answer(&ans);
	}
}
