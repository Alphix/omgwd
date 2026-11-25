// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "omgwd.h"

/* a stand-in AAAA we advertised (to withdraw it if the instance turns native) */
struct adv {
	struct list_head list;
	char net[32];
	char origin[32]; /* where the device lives */
	uint8_t instance[DNAME_MAX + 1];
	uint8_t host[DNAME_MAX + 1];
	struct in6_addr addr;
	uint16_t class;
	int64_t expires;
};

static LIST_HEAD(advs);

static bool str_in(const char *s, char **v, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (!strcmp(s, v[i]))
			return true;
	return false;
}

/* does any link from A to B allow this name? */
static bool pair_allows(const struct iface *a, const struct iface *b,
			const uint8_t *name)
{
	struct link *l;

	list_for_each_entry(l, &config.links, list)
		if (!strcmp(l->from, a->name) &&
		    str_in(b->name, l->to, l->n_to) &&
		    (!name || link_allows(l, name)))
			return true;
	return false;
}

static bool pair_unfiltered(const struct iface *a, const struct iface *b)
{
	struct link *l;

	list_for_each_entry(l, &config.links, list)
		if (!strcmp(l->from, a->name) &&
		    str_in(b->name, l->to, l->n_to) && !l->n_services)
			return true;
	return false;
}

static bool standins_enabled(const struct iface *b)
{
	return config.xlat != XLAT_NONE && b->has_ula;
}

static void quirks(const struct iface *a, const uint8_t *instance,
		   const uint8_t *host, struct ov_result *r)
{
	struct ov_subject s = { .network = a->name,
				.instance = instance,
				.host = host };

	override_eval(&s, r);
}

static bool native(const struct ov_result *r, const uint8_t *instance)
{
	if (r->v[OV_NATIVE] != OV_AUTO)
		return r->v[OV_NATIVE] == OV_ON;
	return state_instance_native_v6(instance);
}

/* translate this instance (served by host) from a to b? */
static bool decide(const struct iface *a, const struct iface *b,
		   const uint8_t *instance, const uint8_t *host)
{
	struct ov_result r;

	if (!pair_allows(a, b, instance))
		return false;
	quirks(a, instance, host, &r);
	if (r.v[OV_TRANSLATE] != OV_AUTO)
		return r.v[OV_TRANSLATE] == OV_ON;
	return !native(&r, instance);
}

/* advertise a stand-in AAAA for host on b? (given that the instance is translated) */
static bool standin_wanted(const struct iface *a, const struct iface *b,
			   const uint8_t *instance, const uint8_t *host)
{
	struct ov_result r;

	if (!standins_enabled(b))
		return false;
	quirks(a, instance, host, &r);
	if (r.v[OV_STANDIN] != OV_AUTO)
		return r.v[OV_STANDIN] == OV_ON;
	/* self link: not under a host name the device has AAAA records for itself */
	return a != b || !state_host_has_aaaa(a->name, host);
}

static void standin_addr(const struct iface *b, const uint8_t *v4,
			 struct in6_addr *out)
{
	iface_standin_prefix(b, out);
	memcpy(&out->s6_addr[12], v4, 4);
}

static void adv_note(const struct iface *orig, const struct iface *b,
		     const uint8_t *instance, const uint8_t *host,
		     const struct in6_addr *addr, uint16_t class, uint32_t ttl)
{
	struct adv *a;

	list_for_each_entry(a, &advs, list)
		if (!strcmp(a->net, b->name) && !memcmp(&a->addr, addr, 16) &&
		    dname_equal(a->host, host))
			goto found;

	a = calloc(1, sizeof(*a));
	if (!a)
		return;
	snprintf(a->net, sizeof(a->net), "%s", b->name);
	dname_copy(a->host, host);
	a->addr = *addr;
	list_add_tail(&a->list, &advs);
	standin_changed(); /* a new stand-in: routes, NDP */
found:
	snprintf(a->origin, sizeof(a->origin), "%s", orig->name);
	dname_copy(a->instance, instance);
	a->class = class;
	a->expires = now_ms() + (int64_t)ttl * 1000;
	if (!ttl)
		a->expires = 0; /* goodbye: forget it */
}

/* ---- IPv4 responses -> IPv6 ---------------------------------------------- */

struct hostsel {
	const uint8_t *host;
	const uint8_t *instance;
};

static const struct hostsel *host_selected(const struct hostsel *h, size_t n,
					   const uint8_t *host)
{
	for (size_t i = 0; i < n; i++)
		if (dname_equal(h[i].host, host))
			return &h[i];
	return NULL;
}

static void select_hosts(const struct iface *a, const struct iface *b,
			 const struct rr_list *l, struct hostsel *h, size_t *n,
			 size_t max)
{
	for (size_t i = 0; i < l->n && *n < max; i++) {
		const struct dns_rr *rr = &l->rr[i];

		if (rr->type != DNS_T_SRV || rr->rdlen < 7)
			continue;
		if (decide(a, b, rr->name, rr->rdata + 6) &&
		    !host_selected(h, *n, rr->rdata + 6)) {
			h[*n].host = rr->rdata + 6;
			h[*n].instance = rr->name;
			(*n)++;
		}
	}
}

/* an A record without its SRV in this packet: find the instance in the state */
static const uint8_t *instance_for_host(const struct iface *a,
					const struct iface *b,
					const uint8_t *host)
{
	struct state_rec *r;

	for (r = state_first(); r; r = state_next(r))
		if (r->rr.type == DNS_T_SRV && r->rr.rdlen > 6 &&
		    !strcmp(r->origin, a->name) &&
		    dname_equal(r->rr.rdata + 6, host) &&
		    decide(a, b, r->rr.name, host))
			return r->rr.name;
	return NULL;
}

/* is this record (owned by an instance or service type) part of what we translate? */
static bool keep_service_rr(const struct iface *a, const struct iface *b,
			    const struct dns_rr *rr)
{
	static uint8_t enum_name[DNAME_MAX + 1];
	const uint8_t *host;

	if (!enum_name[0])
		dname_from_str(enum_name, "_services._dns-sd._udp.local");

	if (rr->type == DNS_T_PTR && rr->rdlen) {
		if (dname_equal(rr->name, enum_name))
			return pair_allows(a, b, rr->rdata);
		/*
		 * service type (or subtype) -> instance: only for instances we know
		 * (an SRV). Other PTRs, e.g. reverse mapping (in-addr.arpa ->
		 * host), aren't ours to translate: on a self link a second
		 * responder of the device claimed the same reverse names in its
		 * probes and took our copies, sent from our address, as conflicts.
		 */
		host = state_srv_target(rr->rdata, NULL);
		return host && pair_allows(a, b, rr->rdata) &&
		       decide(a, b, rr->rdata, host);
	}
	if (rr->type == DNS_T_SRV || rr->type == DNS_T_TXT ||
	    rr->type == DNS_T_NSEC) {
		host = rr->type == DNS_T_SRV && rr->rdlen > 6 ?
			       rr->rdata + 6 :
			       state_srv_target(rr->name, NULL);
		/* an instance we know (or this SRV) */
		return host && decide(a, b, rr->name, host);
	}
	return false;
}

static int put_translated(struct wire_buf *w, int section,
			  const struct iface *a, const struct iface *b,
			  const struct rr_list *l, const struct hostsel *h,
			  size_t n_h, size_t *n_put)
{
	for (size_t i = 0; i < l->n; i++) {
		const struct dns_rr *rr = &l->rr[i];
		const struct hostsel *sel = host_selected(h, n_h, rr->name);
		const uint8_t *instance = sel ? sel->instance : NULL;

		if (!sel && (rr->type == DNS_T_A || rr->type == DNS_T_AAAA ||
			     rr->type == DNS_T_NSEC))
			instance = instance_for_host(a, b, rr->name);

		if (instance &&
		    (rr->type == DNS_T_AAAA || rr->type == DNS_T_NSEC))
			continue; /* the device's own; we add stand-ins instead */

		if (instance && rr_link_local_addr(rr))
			continue; /* 169.254/16: unreachable from b, no stand-in */

		if (instance && rr->type == DNS_T_A && rr->rdlen == 4) {
			if (answer_suppress(b, rr)) {
				/* sent within a second: leave out (the stand-in too) */
			} else if (wire_put_rr(w, section, rr, rr->ttl) &&
				   section != WIRE_AR) {
				return -1;
			} else {
				(*n_put)++;
			}
			if (standin_wanted(a, b, instance, rr->name)) {
				struct dns_rr aaaa = *rr;
				struct in6_addr s6;

				standin_addr(b, rr->rdata, &s6);
				aaaa.type = DNS_T_AAAA;
				aaaa.rdlen = 16;
				aaaa.rdata = s6.s6_addr;
				adv_note(a, b, instance, rr->name, &s6,
					 rr->class, rr->ttl);
				if (answer_suppress(b, &aaaa))
					continue;
				if (wire_put_rr(w, section, &aaaa, rr->ttl) &&
				    section != WIRE_AR)
					return -1;
				(*n_put)++;
			}
			continue;
		}

		if (!instance && keep_service_rr(a, b, rr) &&
		    !answer_suppress(b, rr)) {
			if (wire_put_rr(w, section, rr, rr->ttl) &&
			    section != WIRE_AR)
				return -1;
			(*n_put)++;
		}
	}
	return 0;
}

static void xlat_response(struct iface *a, struct iface *b,
			  const struct dns_msg *m)
{
	struct hostsel h[32];
	size_t n_h = 0, n_put = 0;
	struct wire_buf w;

	select_hosts(a, b, &m->an, h, &n_h, ARRAY_SIZE(h));
	select_hosts(a, b, &m->ar, h, &n_h, ARRAY_SIZE(h));

	if (wire_init(&w, 9000) || wire_put_header(&w, 0, m->flags) ||
	    put_translated(&w, WIRE_AN, a, b, &m->an, h, n_h, &n_put) ||
	    put_translated(&w, WIRE_NS, a, b, &m->ns, h, n_h, &n_put) ||
	    put_translated(&w, WIRE_AR, a, b, &m->ar, h, n_h, &n_put)) {
		log_debug("%s -> %s: cannot build the translated response",
			  a->name, b->name);
		goto out;
	}

	if (n_put && !mdns_send(b, AF_INET6, w.buf, w.len))
		b->tx_translated++;
out:
	wire_free(&w);
}

/* ---- IPv6 queries -> IPv4 --------------------------------------------------- */

static bool host_allowed(const struct iface *a, const struct iface *b,
			 const uint8_t *host)
{
	return pair_unfiltered(a, b) || instance_for_host(a, b, host);
}

static void xlat_query(struct iface *a, struct iface *b,
		       const struct dns_msg *m)
{
	struct wire_buf w;
	size_t n_q = 0;

	if (wire_init(&w, 9000) || wire_put_header(&w, 0, m->flags))
		goto out;

	for (size_t i = 0; i < m->n_qd; i++) {
		const struct dns_question *q = &m->qd[i];
		uint16_t type = q->type;

		if (type == DNS_T_AAAA)
			type = DNS_T_A; /* the device has an A; we add the stand-in */
		if (type == DNS_T_A ? !host_allowed(a, b, q->name) :
				      !pair_allows(a, b, q->name))
			continue;
		if (wire_put_question(&w, q->name, type, q->class & 0x7fff))
			goto out;
		n_q++;
	}

	if (n_q && !mdns_send(a, AF_INET, w.buf, w.len))
		a->tx_translated++;
out:
	wire_free(&w);
}

void xlat_packet(struct iface *in, int family, const struct dns_msg *m)
{
	bool response = m->flags & DNS_F_QR;
	struct iface *t;

	if (!config.enabled)
		return;

	if (response && family == AF_INET) {
		avl_for_each_element(&ifaces, t,
				     avl) if (t->up && pair_allows(in, t, NULL))
			xlat_response(in, t, m);
	} else if (!response && family == AF_INET6 && !m->ns.n) {
		avl_for_each_element(&ifaces, t,
				     avl) if (t->up && pair_allows(t, in, NULL))
			xlat_query(t, in, m);
	}
}

/* ---- helpers for answering from state (answer.c) ---------------------------- */

bool xlat_pair_allows(const struct iface *a, const struct iface *b,
		      const uint8_t *name)
{
	return pair_allows(a, b, name);
}

bool xlat_decide(const struct iface *a, const struct iface *b,
		 const uint8_t *instance, const uint8_t *host)
{
	return decide(a, b, instance, host);
}

const uint8_t *xlat_instance_for_host(const struct iface *a,
				      const struct iface *b,
				      const uint8_t *host)
{
	return instance_for_host(a, b, host);
}

/* the stand-in AAAA for this A record of host on b (false: none wanted there) */
bool xlat_standin_for(const struct iface *a, const struct iface *b,
		      const uint8_t *instance, const uint8_t *host,
		      const uint8_t *v4, struct in6_addr *out)
{
	if (!standin_wanted(a, b, instance, host))
		return false;
	standin_addr(b, v4, out);
	return true;
}

void xlat_note_standin(const struct iface *a, const struct iface *b,
		       const uint8_t *instance, const uint8_t *host,
		       const struct in6_addr *addr, uint16_t class,
		       uint32_t ttl)
{
	adv_note(a, b, instance, host, addr, class, ttl);
}

/* ---- withdrawing stand-ins -------------------------------------------------- */

static void send_goodbye(struct iface *b, struct adv *ad)
{
	struct dns_rr rr = {
		.type = DNS_T_AAAA,
		.class = ad->class,
		.ttl = 0,
		.rdlen = 16,
		.rdata = ad->addr.s6_addr,
	};
	struct wire_buf w;

	dname_copy(rr.name, ad->host);
	if (!wire_init(&w, 9000) &&
	    !wire_put_header(&w, 0, DNS_F_QR | DNS_F_AA) &&
	    !wire_put_rr(&w, WIRE_AN, &rr, 0) &&
	    !mdns_send(b, AF_INET6, w.buf, w.len))
		b->tx_translated++;
	wire_free(&w);
}

void xlat_state_changed(void)
{
	int64_t now = now_ms();
	struct adv *ad, *tmp;

	list_for_each_entry_safe(ad, tmp, &advs, list) {
		struct iface *b = iface_by_name(ad->net),
			     *a = iface_by_name(ad->origin);
		bool withdraw;

		if (ad->expires <= now || !b) {
			list_del(&ad->list);
			free(ad);
			standin_changed();
			continue;
		}

		/* no longer translated, or no stand-in wanted any more */
		withdraw = !a || !decide(a, b, ad->instance, ad->host) ||
			   !standin_wanted(a, b, ad->instance, ad->host);
		if (!withdraw)
			continue;

		{
			char name[DNAME_STR_MAX];

			dname_to_display(ad->host, name, sizeof(name));
			log_info("%s: withdrawing the stand-in of %s", b->name,
				 name);
		}
		send_goodbye(b, ad);
		list_del(&ad->list);
		free(ad);
		standin_changed();
	}
}

void xlat_foreach_standin(standin_cb cb, void *priv)
{
	int64_t now = now_ms();
	struct adv *ad;

	list_for_each_entry(ad, &advs, list)
		if (ad->expires > now)
			cb(ad->net, &ad->addr, priv);
}

bool xlat_standin_active(const char *net, const struct in6_addr *addr)
{
	int64_t now = now_ms();
	struct adv *ad;

	list_for_each_entry(ad, &advs, list)
		if (ad->expires > now && !memcmp(&ad->addr, addr, 16) &&
		    !strcmp(ad->net, net))
			return true;
	return false;
}

/* ---- ubus: the devices we see and what we do with them ----------------------- */

static const char *why_translated(const struct iface *a, const struct iface *t,
				  const uint8_t *instance, const uint8_t *host)
{
	struct ov_result r;

	if (!pair_allows(a, t, instance))
		return "filtered by link";
	quirks(a, instance, host, &r);
	if (r.v[OV_TRANSLATE] == OV_ON)
		return "forced by configuration";
	if (r.v[OV_TRANSLATE] == OV_OFF)
		return "disabled by configuration";
	if (r.v[OV_NATIVE] == OV_ON)
		return "native IPv6 by configuration";
	if (r.v[OV_NATIVE] == OV_OFF)
		return "IPv4-only by configuration";
	return state_instance_native_v6(instance) ? "native IPv6 seen" :
						    "IPv4-only mDNS";
}

static const char *why_no_standin(const struct iface *a, const struct iface *t,
				  const uint8_t *instance, const uint8_t *host)
{
	struct ov_result r;

	if (!standins_enabled(t))
		return t->has_ula ? "stand-ins disabled" :
				    "no ULA on the network";
	quirks(a, instance, host, &r);
	if (r.v[OV_STANDIN] == OV_OFF)
		return "disabled by configuration";
	return "own AAAA on its network";
}

void xlat_dump(struct blob_buf *b)
{
	void *arr = blobmsg_open_array(b, "devices");
	struct state_rec *r, *x;

	for (r = state_first(); r; r = state_next(r)) {
		char buf[DNAME_STR_MAX], abuf[INET6_ADDRSTRLEN];
		const uint8_t *host;
		struct iface *a, *t;
		void *tbl, *v;

		if (r->rr.type != DNS_T_SRV || r->rr.rdlen < 7)
			continue;
		a = iface_by_name(r->origin);
		host = r->rr.rdata + 6;

		tbl = blobmsg_open_table(b, NULL);
		dname_to_display(r->rr.name, buf, sizeof(buf));
		blobmsg_add_string(b, "instance", buf);
		blobmsg_add_string(b, "network", r->origin);
		dname_to_display(host, buf, sizeof(buf));
		blobmsg_add_string(b, "host", buf);
		blobmsg_add_u32(b, "port",
				(r->rr.rdata[4] << 8) | r->rr.rdata[5]);
		blobmsg_add_u8(b, "native_ipv6",
			       state_instance_native_v6(r->rr.name));

		v = blobmsg_open_array(b, "ipv4");
		for (x = state_first(); x; x = state_next(x))
			if (x->rr.type == DNS_T_A && x->rr.rdlen == 4 &&
			    !rr_link_local_addr(&x->rr) &&
			    !strcmp(x->origin, r->origin) &&
			    dname_equal(x->rr.name, host))
				blobmsg_add_string(b, NULL,
						   inet_ntop(AF_INET,
							     x->rr.rdata, abuf,
							     sizeof(abuf)));
		blobmsg_close_array(b, v);

		v = blobmsg_open_array(b, "translated_to");
		avl_for_each_element(&ifaces, t, avl)
		{
			bool translated;
			void *e;

			if (!a || !pair_allows(a, t, NULL))
				continue;
			translated = decide(a, t, r->rr.name, host);
			e = blobmsg_open_table(b, NULL);
			blobmsg_add_string(b, "network", t->name);
			blobmsg_add_u8(b, "translated", translated);
			blobmsg_add_string(b, "reason",
					   why_translated(a, t, r->rr.name,
							  host));
			if (translated &&
			    standin_wanted(a, t, r->rr.name, host)) {
				for (x = state_first(); x; x = state_next(x))
					if (x->rr.type == DNS_T_A &&
					    x->rr.rdlen == 4 &&
					    !rr_link_local_addr(&x->rr) &&
					    !strcmp(x->origin, r->origin) &&
					    dname_equal(x->rr.name, host)) {
						struct in6_addr s6;

						standin_addr(t, x->rr.rdata,
							     &s6);
						blobmsg_add_string(
							b, "standin",
							inet_ntop(AF_INET6, &s6,
								  abuf,
								  sizeof(abuf)));
						break;
					}
			} else if (translated) {
				blobmsg_add_string(
					b, "no_standin",
					why_no_standin(a, t, r->rr.name, host));
			}
			blobmsg_close_table(b, e);
		}
		blobmsg_close_array(b, v);
		blobmsg_close_table(b, tbl);
	}
	blobmsg_close_array(b, arr);
}
