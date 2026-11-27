// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <uci.h>

#include "omgwd.h"

struct config config = {
	.links = LIST_HEAD_INIT(config.links),
	.overrides = LIST_HEAD_INIT(config.overrides),
};

const char *ndp_mode_name(enum ndp_mode m)
{
	return m == NDP_KERNEL ? "kernel" : "self";
}

const char *xlat_mode_name(enum xlat_mode m)
{
	switch (m) {
	case XLAT_IPXLAT:
		return "ipxlat";
	case XLAT_BPF:
		return "bpf";
	case XLAT_NONE:
		return "none";
	default:
		return "auto";
	}
}

static void strv_free(char **v, size_t n)
{
	for (size_t i = 0; i < n; i++)
		free(v[i]);
	free(v);
}

static bool strv_add(char ***v, size_t *n, const char *s)
{
	char **nv = realloc(*v, (*n + 1) * sizeof(*nv));

	if (!nv)
		return false;
	*v = nv;
	nv[*n] = strdup(s);
	if (!nv[*n])
		return false;
	(*n)++;
	return true;
}

void config_free(struct config *c)
{
	struct link *l, *tmp;

	overrides_free(&c->overrides);

	list_for_each_entry_safe(l, tmp, &c->links, list) {
		list_del(&l->list);
		free(l->name);
		free(l->from);
		strv_free(l->to, l->n_to);
		strv_free(l->services, l->n_services);
		free(l->svc_names);
		free(l);
	}
}

bool config_uses_network(const char *name)
{
	struct link *l;

	list_for_each_entry(l, &config.links, list) {
		if (!strcmp(l->from, name))
			return true;
		for (size_t i = 0; i < l->n_to; i++)
			if (!strcmp(l->to[i], name))
				return true;
	}
	return false;
}

/* may this link carry records of 'name' (a service type, subtype, instance)? */
bool link_allows(const struct link *l, const uint8_t *name)
{
	if (!l->n_services)
		return true;
	for (size_t i = 0; i < l->n_services; i++)
		if (dname_is_subdomain(name, l->svc_names[i]))
			return true;
	return false;
}

static bool opt_bool(struct uci_section *s, const char *name, bool def)
{
	const char *v = uci_lookup_option_string(s->package->ctx, s, name);

	if (!v)
		return def;
	return !strcmp(v, "1") || !strcmp(v, "on") || !strcmp(v, "yes") ||
	       !strcmp(v, "true");
}

static bool parse_main(struct uci_section *s, struct config *c)
{
	struct uci_context *ctx = s->package->ctx;
	const char *v;

	c->enabled = opt_bool(s, "enabled", true);
	c->answer_from_state = opt_bool(s, "answer_from_state", true);

	v = uci_lookup_option_string(ctx, s, "ndp");
	if (!v || !strcmp(v, "self"))
		c->ndp = NDP_SELF;
	else if (!strcmp(v, "kernel"))
		c->ndp = NDP_KERNEL;
	else {
		log_err("invalid ndp '%s' (self, kernel)", v);
		return false;
	}

	v = uci_lookup_option_string(ctx, s, "pool4");
	if (v && inet_pton(AF_INET, v, &c->pool4) != 1) {
		log_err("invalid pool4 '%s'", v);
		return false;
	}

	v = uci_lookup_option_string(ctx, s, "pref64");
	if (v) {
		char buf[INET6_ADDRSTRLEN + 4], *slash;

		c->has_pref64 = false;
		if (*v && strcmp(v, "none")) {
			snprintf(buf, sizeof(buf), "%s", v);
			slash = strchr(buf, '/');
			if (slash)
				*slash = '\0';
			if (inet_pton(AF_INET6, buf, &c->pref64) != 1 ||
			    (slash && strcmp(slash + 1, "96"))) {
				log_err("invalid pref64 '%s' (an IPv6 /96)", v);
				return false;
			}
			c->has_pref64 = true;
		}
	}

	v = uci_lookup_option_string(ctx, s, "xlat");
	if (!v || !strcmp(v, "auto"))
		c->xlat = XLAT_AUTO;
	else if (!strcmp(v, "ipxlat"))
		c->xlat = XLAT_IPXLAT;
	else if (!strcmp(v, "bpf"))
		c->xlat = XLAT_BPF;
	else if (!strcmp(v, "none"))
		c->xlat = XLAT_NONE;
	else {
		log_err("invalid xlat '%s' (auto, ipxlat, bpf, none)", v);
		return false;
	}

	return true;
}

static bool add_list(struct uci_section *s, const char *name, char ***v,
		     size_t *n)
{
	struct uci_option *o = uci_lookup_option(s->package->ctx, s, name);
	struct uci_element *e;

	if (!o)
		return true;
	if (o->type == UCI_TYPE_STRING)
		return strv_add(v, n, o->v.string);
	uci_foreach_element(&o->v.list,
			    e) if (!strv_add(v, n, e->name)) return false;
	return true;
}

static bool parse_link(struct uci_section *s, struct config *c)
{
	struct uci_context *ctx = s->package->ctx;
	const char *from = uci_lookup_option_string(ctx, s, "from");
	struct link *l;

	if (!from) {
		log_err("link '%s' without 'from'", s->e.name);
		return false;
	}

	l = calloc(1, sizeof(*l));
	if (!l)
		return false;
	l->name = strdup(s->e.name);
	l->from = strdup(from);
	list_add_tail(&l->list, &c->links);

	if (!l->name || !l->from || !add_list(s, "to", &l->to, &l->n_to) ||
	    !add_list(s, "service", &l->services, &l->n_services))
		return false;

	if (!l->n_to) {
		log_err("link '%s' without 'to'", s->e.name);
		return false;
	}

	if (l->n_services) {
		l->svc_names = calloc(l->n_services, sizeof(*l->svc_names));
		if (!l->svc_names)
			return false;
		for (size_t i = 0; i < l->n_services; i++) {
			char buf[DNAME_STR_MAX];

			snprintf(buf, sizeof(buf), "%s.local", l->services[i]);
			if (dname_from_str(l->svc_names[i], buf) < 0) {
				log_err("link '%s': invalid service '%s'",
					s->e.name, l->services[i]);
				return false;
			}
		}
	}
	return true;
}

bool config_load(void)
{
	struct uci_context *ctx = uci_alloc_context();
	struct config c = { .links = LIST_HEAD_INIT(c.links),
			    .overrides = LIST_HEAD_INIT(c.overrides) };
	struct uci_package *pkg = NULL;
	struct uci_element *e;
	bool have_main = false;
	bool ok = false;

	if (!ctx)
		return false;
	if (uci_confdir)
		uci_set_confdir(ctx, uci_confdir);

	/* the quirk table first: the configuration's overrides come after it */
	overrides_load_quirks(&c.overrides);

	if (uci_load(ctx, "omgwd", &pkg) || !pkg) {
		log_err("cannot load the omgwd configuration");
		goto out;
	}

	uci_foreach_element(&pkg->sections, e)
	{
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "omgwd")) {
			if (have_main)
				continue;
			have_main = true;
			if (!parse_main(s, &c))
				goto out;
		} else if (!strcmp(s->type, "link")) {
			if (!parse_link(s, &c))
				goto out;
		} else if (!strcmp(s->type, "override")) {
			if (!overrides_parse_section(s, &c.overrides))
				goto out;
		}
	}

	if (!c.pool4.s_addr)
		inet_pton(AF_INET, "100.127.255.0", &c.pool4);
	c.pool4.s_addr &= htonl(0xffffff00);

	if (!have_main) {
		/* all defaults */
		c.enabled = true;
		c.answer_from_state = true;
	}

	config_free(&config);
	config.enabled = c.enabled;
	config.answer_from_state = c.answer_from_state;
	config.ndp = c.ndp;
	config.xlat = c.xlat;
	config.pool4 = c.pool4;
	config.has_pref64 = c.has_pref64;
	config.pref64 = c.pref64;
	list_splice_init(&c.links, &config.links);
	list_splice_init(&c.overrides, &config.overrides);
	ok = true;

	log_info(
		"configuration loaded: %s, ndp %s, xlat %s, answer from state %s",
		config.enabled ? "enabled" : "disabled",
		ndp_mode_name(config.ndp), xlat_mode_name(config.xlat),
		config.answer_from_state ? "on" : "off");
out:
	if (!ok)
		config_free(&c);
	uci_free_context(ctx);
	return ok;
}
