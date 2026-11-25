// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <string.h>

#include "omgwd.h"

#define MAX_SVC 64

/* what may be repeated to one target network */
struct svcset {
	bool all;
	const uint8_t *names[MAX_SVC];
	size_t n;
};

static bool str_in(const char *s, char **v, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (!strcmp(s, v[i]))
			return true;
	return false;
}

static void svcset_add_link(struct svcset *set, const struct link *l)
{
	if (!l->n_services) {
		set->all = true;
		return;
	}
	for (size_t i = 0; i < l->n_services && set->n < MAX_SVC; i++)
		set->names[set->n++] = l->svc_names[i];
}

/* does 'in' feed 'target' for this kind of message? Returns false if not at all */
static bool collect(const struct iface *in, const struct iface *target,
		    bool response, struct svcset *set)
{
	struct link *l;
	bool any = false;

	memset(set, 0, sizeof(*set));
	list_for_each_entry(l, &config.links, list) {
		bool match;

		/* a self link (from A to A) never matches: target != in */
		if (response)
			match = !strcmp(l->from, in->name) &&
				str_in(target->name, l->to, l->n_to);
		else
			match = !strcmp(l->from, target->name) &&
				str_in(in->name, l->to, l->n_to);

		if (match) {
			svcset_add_link(set, l);
			any = true;
		}
	}
	return any;
}

static bool name_in_set(const uint8_t *name, const struct svcset *set)
{
	for (size_t i = 0; i < set->n; i++)
		if (dname_is_subdomain(name, set->names[i]))
			return true;
	return false;
}

static const uint8_t *services_enum_name(void)
{
	static uint8_t name[DNAME_MAX + 1];

	if (!name[0])
		dname_from_str(name, "_services._dns-sd._udp.local");
	return name;
}

/* SRV rdata: priority, weight, port, target (uncompressed after parsing) */
static const uint8_t *srv_target(const struct dns_rr *rr)
{
	if (rr->type != DNS_T_SRV || rr->rdlen < 7)
		return NULL;
	return rr->rdata + 6;
}

/* ---- per-device knobs (linklocal, repeat) -------------------------------------- */

static bool knobs_active; /* any override sets linklocal or repeat */

/* the instance and host a record belongs to, from the message or the state */
static void rr_subject(const struct iface *in, const struct dns_msg *m,
		       const struct dns_rr *rr, struct ov_subject *s)
{
	const struct rr_list *lists[] = { &m->an, &m->ns, &m->ar };

	memset(s, 0, sizeof(*s));
	s->network = in->name;
	switch (rr->type) {
	case DNS_T_PTR:
		if (!rr->rdlen || dname_equal(rr->name, services_enum_name()))
			return;
		s->instance = rr->rdata;
		break;
	case DNS_T_SRV:
	case DNS_T_TXT:
		s->instance = rr->name;
		break;
	case DNS_T_A:
	case DNS_T_AAAA:
		s->host = rr->name;
		break;
	case DNS_T_NSEC:
		s->instance =
			rr->name; /* or a host: one of the two matches below */
		s->host = rr->name;
		break;
	default:
		return;
	}

	/* the other half: the SRV of the instance, or the SRV pointing at the host */
	for (size_t k = 0; k < ARRAY_SIZE(lists); k++)
		for (size_t i = 0; i < lists[k]->n; i++) {
			const struct dns_rr *srv = &lists[k]->rr[i];
			const uint8_t *t = srv_target(srv);

			if (!t)
				continue;
			if (s->instance && !s->host &&
			    dname_equal(srv->name, s->instance)) {
				s->host = t;
				return;
			}
			if (s->host && !s->instance &&
			    dname_equal(t, s->host)) {
				s->instance = srv->name;
				return;
			}
		}
	for (struct state_rec *r = state_first(); r; r = state_next(r)) {
		const uint8_t *t = srv_target(&r->rr);

		if (!t || strcmp(r->origin, in->name))
			continue;
		if (s->instance && !s->host &&
		    dname_equal(r->rr.name, s->instance)) {
			s->host = t;
			return;
		}
		if (s->host && !s->instance && dname_equal(t, s->host)) {
			s->instance = r->rr.name;
			return;
		}
	}
}

/* leave this record out when repeating from in? */
static bool rr_dropped(const struct iface *in, const struct dns_msg *m,
		       const struct dns_rr *rr)
{
	struct ov_subject s;
	struct ov_result r;

	if (!knobs_active)
		return rr_link_local_addr(rr);
	rr_subject(in, m, rr, &s);
	override_eval(&s, &r);
	if (r.v[OV_REPEAT] == OV_OFF)
		return true;
	return rr_link_local_addr(rr) && r.v[OV_LINKLOCAL] != OV_ON;
}

static bool rr_in_set(const struct dns_rr *rr, const struct svcset *set,
		      const uint8_t **targets, size_t n_targets)
{
	if (set->all)
		return true;

	if (name_in_set(rr->name, set))
		return true;

	/* DNS-SD service type enumeration pointing at one of our services */
	if (rr->type == DNS_T_PTR &&
	    dname_equal(rr->name, services_enum_name()) &&
	    name_in_set(rr->rdata, set))
		return true;

	/* addresses (and NSEC) of hosts our services' SRV records point to */
	if (rr->type == DNS_T_A || rr->type == DNS_T_AAAA ||
	    rr->type == DNS_T_NSEC)
		for (size_t i = 0; i < n_targets; i++)
			if (dname_equal(rr->name, targets[i]))
				return true;

	return false;
}

static void collect_targets(const struct rr_list *l, const struct svcset *set,
			    const uint8_t **targets, size_t *n, size_t max)
{
	for (size_t i = 0; i < l->n && *n < max; i++) {
		const uint8_t *t = srv_target(&l->rr[i]);

		if (t && name_in_set(l->rr[i].name, set))
			targets[(*n)++] = t;
	}
}

static int put_section(struct wire_buf *w, int section, const struct iface *in,
		       const struct dns_msg *m, const struct rr_list *l,
		       const struct svcset *set, const uint8_t **targets,
		       size_t n_targets, size_t *n_put)
{
	for (size_t i = 0; i < l->n; i++) {
		if (!rr_in_set(&l->rr[i], set, targets, n_targets) ||
		    rr_dropped(in, m, &l->rr[i]))
			continue;
		if (wire_put_rr(w, section, &l->rr[i], l->rr[i].ttl) &&
		    section != WIRE_AR)
			return -1;
		(*n_put)++;
	}
	return 0;
}

/* rebuild m for one target: QU cleared, only what the set allows */
static int build(struct wire_buf *w, const struct iface *in,
		 const struct dns_msg *m, const struct svcset *set,
		 bool response)
{
	const uint8_t *targets[32];
	size_t n_targets = 0, n_q = 0, n_rr = 0;

	if (wire_init(w, 9000) || wire_put_header(w, m->id, m->flags))
		return -1;

	if (!set->all) {
		collect_targets(&m->an, set, targets, &n_targets,
				ARRAY_SIZE(targets));
		collect_targets(&m->ar, set, targets, &n_targets,
				ARRAY_SIZE(targets));
	}

	for (size_t i = 0; i < m->n_qd; i++) {
		const struct dns_question *q = &m->qd[i];

		if (!set->all && !name_in_set(q->name, set) &&
		    !(q->type == DNS_T_PTR &&
		      dname_equal(q->name, services_enum_name())))
			continue;
		if (wire_put_question(w, q->name, q->type, q->class & 0x7fff))
			return -1;
		n_q++;
	}

	if (put_section(w, WIRE_AN, in, m, &m->an, set, targets, n_targets,
			&n_rr) ||
	    put_section(w, WIRE_NS, in, m, &m->ns, set, targets, n_targets,
			&n_rr) ||
	    put_section(w, WIRE_AR, in, m, &m->ar, set, targets, n_targets,
			&n_rr))
		return -1;

	/* nothing left worth sending */
	if (response ? !n_rr : !n_q)
		return 1;
	return 0;
}

static bool has_link_local(const struct rr_list *l)
{
	for (size_t i = 0; i < l->n; i++)
		if (rr_link_local_addr(&l->rr[i]))
			return true;
	return false;
}

void repeat_packet(struct iface *in, int family, const uint8_t *buf, size_t len,
		   const struct dns_msg *m)
{
	bool response = m->flags & DNS_F_QR;
	bool verbatim;
	struct iface *t;

	if (!config.enabled)
		return;

	knobs_active = override_sets(OV_LINKLOCAL) || override_sets(OV_REPEAT);
	verbatim = response && !knobs_active && !has_link_local(&m->an) &&
		   !has_link_local(&m->ns) && !has_link_local(&m->ar);

	avl_for_each_element(&ifaces, t, avl)
	{
		struct svcset set;
		struct wire_buf w;
		int ret;

		if (t == in || !t->up || !collect(in, t, response, &set))
			continue;

		if (verbatim && set.all) {
			if (!mdns_send(t, family, buf, len))
				t->tx_repeated++;
			continue;
		}

		ret = build(&w, in, m, &set, response);
		if (!ret && !mdns_send(t, family, w.buf, w.len))
			t->tx_repeated++;
		else if (ret < 0)
			log_debug("%s -> %s: cannot rebuild the message",
				  in->name, t->name);
		wire_free(&w);
	}
}
