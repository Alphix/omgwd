// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <arpa/inet.h>
#include <dirent.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <uci.h>

#include "omgwd.h"

const char *quirk_dir = "/usr/share/omgwd/quirks.d";

struct ov_subnet {
	uint32_t addr, mask; /* host order */
};

struct override {
	struct list_head list;
	char *name; /* "<file>:<section>" */
	char **networks;
	size_t n_networks;
	char **hosts; /* glob patterns, without .local */
	size_t n_hosts;
	uint8_t (*services)[DNAME_MAX + 1]; /* "<type>.local" */
	size_t n_services;
	char **instances; /* glob patterns for the instance label */
	size_t n_instances;
	struct ov_subnet *ipv4;
	size_t n_ipv4;
	enum ov_value knob[OV_KNOBS];
};

static const struct {
	const char *option;
	const char *on, *off;
} knobs[OV_KNOBS] = {
	[OV_TRANSLATE] = { "translate", "always", "never" },
	[OV_NATIVE] = { "native", "yes", "no" },
	[OV_STANDIN] = { "standin", "always", "never" },
	[OV_LINKLOCAL] = { "linklocal", "keep", "drop" },
	[OV_REPEAT] = { "repeat", "yes", "no" },
};

const char *ov_knob_name(enum ov_knob k)
{
	return knobs[k].option;
}

/* ---- parsing ------------------------------------------------------------------ */

static void free_strv(char **v, size_t n)
{
	for (size_t i = 0; i < n; i++)
		free(v[i]);
	free(v);
}

static void override_free(struct override *o)
{
	free(o->name);
	free_strv(o->networks, o->n_networks);
	free_strv(o->hosts, o->n_hosts);
	free(o->services);
	free_strv(o->instances, o->n_instances);
	free(o->ipv4);
	free(o);
}

void overrides_free(struct list_head *l)
{
	struct override *o, *tmp;

	list_for_each_entry_safe(o, tmp, l, list) {
		list_del(&o->list);
		override_free(o);
	}
}

/* the values of an option or list, as strings */
static bool get_list(struct uci_section *s, const char *name, char ***out,
		     size_t *n)
{
	struct uci_option *o = uci_lookup_option(s->package->ctx, s, name);
	struct uci_element *e;

	*out = NULL;
	*n = 0;
	if (!o)
		return true;
	if (o->type == UCI_TYPE_STRING) {
		*out = calloc(1, sizeof(char *));
		if (!*out || !(**out = strdup(o->v.string)))
			return false;
		*n = 1;
		return true;
	}
	uci_foreach_element(&o->v.list, e)
	{
		char **v = realloc(*out, (*n + 1) * sizeof(char *));

		if (!v)
			return false;
		*out = v;
		if (!(v[*n] = strdup(e->name)))
			return false;
		(*n)++;
	}
	return true;
}

static void strip_local(char *s)
{
	size_t n = strlen(s);

	if (n > 6 && !strcasecmp(s + n - 6, ".local"))
		s[n - 6] = '\0';
	else if (n > 7 && !strcasecmp(s + n - 7, ".local."))
		s[n - 7] = '\0';
}

static bool parse_subnet(const char *s, struct ov_subnet *out)
{
	char buf[32], *slash;
	struct in_addr a;
	long bits = 32;

	snprintf(buf, sizeof(buf), "%s", s);
	slash = strchr(buf, '/');
	if (slash) {
		char *end;

		*slash = '\0';
		bits = strtol(slash + 1, &end, 10);
		if (*end || bits < 0 || bits > 32)
			return false;
	}
	if (inet_pton(AF_INET, buf, &a) != 1)
		return false;
	out->mask = bits ? 0xffffffffu << (32 - bits) : 0;
	out->addr = ntohl(a.s_addr) & out->mask;
	return true;
}

static bool parse_override(struct uci_section *s, const char *origin,
			   struct list_head *out)
{
	struct uci_context *ctx = s->package->ctx;
	struct override *o = calloc(1, sizeof(*o));
	char **v = NULL, name[128];
	size_t n = 0;
	bool any_knob = false;

	snprintf(name, sizeof(name), "%s:%s", origin, s->e.name);
	if (!o || !(o->name = strdup(name)))
		goto oom;

	if (!get_list(s, "network", &o->networks, &o->n_networks) ||
	    !get_list(s, "host", &o->hosts, &o->n_hosts) ||
	    !get_list(s, "instance", &o->instances, &o->n_instances))
		goto oom;
	for (size_t i = 0; i < o->n_hosts; i++)
		strip_local(o->hosts[i]);

	if (!get_list(s, "service", &v, &n))
		goto oom;
	if (n) {
		o->services = calloc(n, sizeof(*o->services));
		if (!o->services)
			goto oom;
		for (size_t i = 0; i < n; i++) {
			char buf[DNAME_STR_MAX];

			strip_local(v[i]);
			snprintf(buf, sizeof(buf), "%s.local", v[i]);
			if (dname_from_str(o->services[i], buf) < 0) {
				log_err("override %s: invalid service '%s'",
					name, v[i]);
				goto err;
			}
		}
		o->n_services = n;
	}
	free_strv(v, n);
	v = NULL;
	n = 0;

	if (!get_list(s, "ipv4", &v, &n))
		goto oom;
	if (n) {
		o->ipv4 = calloc(n, sizeof(*o->ipv4));
		if (!o->ipv4)
			goto oom;
		for (size_t i = 0; i < n; i++)
			if (!parse_subnet(v[i], &o->ipv4[i])) {
				log_err("override %s: invalid ipv4 '%s'", name,
					v[i]);
				goto err;
			}
		o->n_ipv4 = n;
	}
	free_strv(v, n);
	v = NULL;
	n = 0;

	for (int k = 0; k < OV_KNOBS; k++) {
		const char *val =
			uci_lookup_option_string(ctx, s, knobs[k].option);

		if (!val)
			continue;
		any_knob = true;
		if (!strcmp(val, "auto"))
			o->knob[k] = OV_AUTO;
		else if (!strcmp(val, knobs[k].on))
			o->knob[k] = OV_ON;
		else if (!strcmp(val, knobs[k].off))
			o->knob[k] = OV_OFF;
		else {
			log_err("override %s: %s must be auto, %s or %s", name,
				knobs[k].option, knobs[k].on, knobs[k].off);
			goto err;
		}
	}
	if (!any_knob)
		log_warn("override %s sets nothing", name);

	list_add_tail(&o->list, out);
	return true;
oom:
	log_err("override %s: out of memory", name);
err:
	free_strv(v, n);
	if (o)
		override_free(o);
	return false;
}

bool overrides_parse_section(struct uci_section *s, struct list_head *out)
{
	return parse_override(s, "config", out);
}

static int filter_quirk(const struct dirent *d)
{
	return d->d_name[0] != '.' && d->d_type != DT_DIR;
}

/* the quirk table: config override sections in UCI files, in lexical order */
void overrides_load_quirks(struct list_head *out)
{
	struct dirent **ents;
	int n;

	if (!quirk_dir || !*quirk_dir)
		return;
	n = scandir(quirk_dir, &ents, filter_quirk, alphasort);
	if (n < 0)
		return; /* no quirk table */

	for (int i = 0; i < n; i++) {
		struct uci_context *ctx = uci_alloc_context();
		struct uci_package *pkg = NULL;
		struct uci_element *e;
		char path[512];

		snprintf(path, sizeof(path), "%s/%s", quirk_dir,
			 ents[i]->d_name);
		if (!ctx)
			break;
		if (uci_load(ctx, path, &pkg) || !pkg) {
			log_warn("quirk table: cannot load %s", path);
		} else {
			uci_foreach_element(&pkg->sections, e)
			{
				struct uci_section *s = uci_to_section(e);

				if (strcmp(s->type, "override"))
					log_warn(
						"quirk table %s: ignoring section type '%s'",
						ents[i]->d_name, s->type);
				else if (!parse_override(s, ents[i]->d_name,
							 out))
					log_warn(
						"quirk table %s: ignoring section '%s'",
						ents[i]->d_name, s->e.name);
			}
		}
		uci_free_context(ctx);
	}
	for (int i = 0; i < n; i++)
		free(ents[i]);
	free(ents);
}

/* ---- matching and evaluation -------------------------------------------------- */

static bool str_in(const char *s, char **v, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (!strcmp(s, v[i]))
			return true;
	return false;
}

/* first label of a name, for humans */
static void first_label(const uint8_t *name, char *buf, size_t len)
{
	char full[DNAME_STR_MAX], *dot;

	dname_to_display(name, full, sizeof(full));
	/* the display form escapes dots inside labels as "\." */
	for (dot = full; (dot = strchr(dot, '.')); dot++)
		if (dot == full || dot[-1] != '\\')
			break;
	if (dot)
		*dot = '\0';
	snprintf(buf, len, "%s", full);
}

static bool glob_any(char **pat, size_t n, const char *s)
{
	for (size_t i = 0; i < n; i++)
		if (!fnmatch(pat[i], s, FNM_CASEFOLD))
			return true;
	return false;
}

static bool host_ipv4_in(const struct ov_subject *s, const struct override *o)
{
	for (struct state_rec *r = state_first(); r; r = state_next(r)) {
		uint32_t a;

		if (r->rr.type != DNS_T_A || r->rr.rdlen != 4 ||
		    strcmp(r->origin, s->network) ||
		    !dname_equal(r->rr.name, s->host))
			continue;
		memcpy(&a, r->rr.rdata, 4);
		a = ntohl(a);
		for (size_t i = 0; i < o->n_ipv4; i++)
			if ((a & o->ipv4[i].mask) == o->ipv4[i].addr)
				return true;
	}
	return false;
}

static bool matches(const struct override *o, const struct ov_subject *s)
{
	char buf[DNAME_STR_MAX];

	if (o->n_networks &&
	    (!s->network || !str_in(s->network, o->networks, o->n_networks)))
		return false;

	if (o->n_hosts) {
		if (!s->host)
			return false;
		dname_to_display(s->host, buf, sizeof(buf));
		strip_local(buf);
		if (!glob_any(o->hosts, o->n_hosts, buf))
			return false;
	}

	if (o->n_services) {
		bool ok = false;

		for (size_t i = 0; s->instance && i < o->n_services; i++)
			if (dname_is_subdomain(s->instance, o->services[i]) &&
			    !dname_equal(s->instance, o->services[i]))
				ok = true;
		if (!ok)
			return false;
	}

	if (o->n_instances) {
		if (!s->instance)
			return false;
		first_label(s->instance, buf, sizeof(buf));
		if (!glob_any(o->instances, o->n_instances, buf))
			return false;
	}

	if (o->n_ipv4 && (!s->host || !s->network || !host_ipv4_in(s, o)))
		return false;

	return true;
}

void override_eval(const struct ov_subject *s, struct ov_result *r)
{
	struct override *o;

	for (int k = 0; k < OV_KNOBS; k++)
		r->v[k] = OV_AUTO;

	list_for_each_entry(o, &config.overrides, list) {
		if (!matches(o, s))
			continue;
		for (int k = 0; k < OV_KNOBS; k++)
			if (o->knob[k] != OV_UNSET)
				r->v[k] = o->knob[k];
	}
}

/* does any override set this knob? (fast paths when nothing is configured) */
bool override_sets(enum ov_knob k)
{
	struct override *o;

	list_for_each_entry(o, &config.overrides, list)
		if (o->knob[k] != OV_UNSET)
			return true;
	return false;
}

void overrides_dump(struct blob_buf *b)
{
	void *a = blobmsg_open_array(b, "overrides");
	struct override *o;

	list_for_each_entry(o, &config.overrides, list) {
		void *t = blobmsg_open_table(b, NULL);

		blobmsg_add_string(b, "name", o->name);
		for (int k = 0; k < OV_KNOBS; k++)
			if (o->knob[k] != OV_UNSET)
				blobmsg_add_string(
					b, knobs[k].option,
					o->knob[k] == OV_AUTO ? "auto" :
					o->knob[k] == OV_ON   ? knobs[k].on :
								knobs[k].off);
		blobmsg_close_table(b, t);
	}
	blobmsg_close_array(b, a);
}
