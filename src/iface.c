// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>

#include <libubus.h>

#include "omgwd.h"

struct avl_tree ifaces;

static struct ubus_request dump_req;
static bool dump_pending;
static bool dump_again; /* an event arrived while a dump was running */
static struct uloop_timeout refresh_timer;
static struct uloop_timeout
	addr_timer; /* addresses change without netifd events (SLAAC) */

static int iface_cmp(const void *a, const void *b, void *ptr)
{
	return strcmp(a, b);
}

/* the stand-in prefix of a client network: <ULA /64>:0:1::/96 (DESIGN.md) */
void iface_standin_prefix(const struct iface *i, struct in6_addr *out)
{
	memset(out, 0, sizeof(*out));
	memcpy(out, &i->ula64, 8);
	out->s6_addr[11] = 1;
}

static void iface_find_ula(struct iface *i, struct ifaddrs *ifa)
{
	i->has_ula = false;

	for (struct ifaddrs *a = ifa; a; a = a->ifa_next) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)a->ifa_addr;
		struct sockaddr_in6 *m = (struct sockaddr_in6 *)a->ifa_netmask;
		int plen = 0;

		if (!s || s->sin6_family != AF_INET6 || !i->device ||
		    strcmp(a->ifa_name, i->device))
			continue;
		/* fc00::/7 with an on-link /64 */
		if ((s->sin6_addr.s6_addr[0] & 0xfe) != 0xfc || !m)
			continue;
		for (int k = 0; k < 16; k++)
			plen += __builtin_popcount(m->sin6_addr.s6_addr[k]);
		if (plen != 64)
			continue;

		memset(&i->ula64, 0, sizeof(i->ula64));
		memcpy(&i->ula64, &s->sin6_addr, 8);
		i->has_ula = true;
		return;
	}
}

static void iface_collect_addrs(struct iface *i, struct ifaddrs *ifa)
{
	free(i->addr4);
	free(i->addr6);
	i->addr4 = NULL;
	i->addr6 = NULL;
	i->n_addr4 = i->n_addr6 = 0;

	for (struct ifaddrs *a = ifa; a; a = a->ifa_next) {
		if (!a->ifa_addr || !i->device ||
		    strcmp(a->ifa_name, i->device))
			continue;
		if (a->ifa_addr->sa_family == AF_INET) {
			struct in_addr *n = realloc(
				i->addr4, (i->n_addr4 + 1) * sizeof(*n));

			if (!n)
				continue;
			i->addr4 = n;
			n[i->n_addr4++] =
				((struct sockaddr_in *)a->ifa_addr)->sin_addr;
		} else if (a->ifa_addr->sa_family == AF_INET6) {
			struct in6_addr *n = realloc(
				i->addr6, (i->n_addr6 + 1) * sizeof(*n));

			if (!n)
				continue;
			i->addr6 = n;
			n[i->n_addr6++] =
				((struct sockaddr_in6 *)a->ifa_addr)->sin6_addr;
		}
	}
}

static void iface_update_addrs(void)
{
	struct ifaddrs *ifa = NULL;
	struct iface *i;

	if (getifaddrs(&ifa))
		ifa = NULL;
	avl_for_each_element(&ifaces, i, avl)
	{
		iface_find_ula(i, ifa);
		iface_collect_addrs(i, ifa);
	}
	if (ifa)
		freeifaddrs(ifa);
}

static void addr_timer_cb(struct uloop_timeout *t)
{
	iface_update_addrs();
	uloop_timeout_set(&addr_timer, 30 * 1000);
}

bool iface_is_own_addr(const struct iface *i, int family, const void *addr)
{
	if (family == AF_INET) {
		for (size_t k = 0; k < i->n_addr4; k++)
			if (!memcmp(&i->addr4[k], addr, 4))
				return true;
	} else {
		for (size_t k = 0; k < i->n_addr6; k++)
			if (!memcmp(&i->addr6[k], addr, 16))
				return true;
	}
	return false;
}

enum { IF_NAME, IF_UP, IF_L3DEV, __IF_MAX };

static const struct blobmsg_policy if_policy[__IF_MAX] = {
	[IF_NAME] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
	[IF_UP] = { .name = "up", .type = BLOBMSG_TYPE_BOOL },
	[IF_L3DEV] = { .name = "l3_device", .type = BLOBMSG_TYPE_STRING },
};

/* keep counters and memberships of networks that are still there */
static void parse_iface(struct blob_attr *data, struct avl_tree *old)
{
	struct blob_attr *tb[__IF_MAX];
	struct iface *i;
	const char *name;

	blobmsg_parse(if_policy, __IF_MAX, tb, blobmsg_data(data),
		      blobmsg_data_len(data));
	if (!tb[IF_NAME])
		return;
	name = blobmsg_get_string(tb[IF_NAME]);
	if (!config_uses_network(name) || avl_find(&ifaces, name))
		return;

	i = avl_find_element(old, name, i, avl);
	if (i) {
		avl_delete(old, &i->avl);
		free(i->device);
		i->device = NULL;
	} else {
		i = calloc(1, sizeof(*i));
		if (!i)
			return;
		i->name = strdup(name);
		i->ndp_fd.fd = -1;
	}

	i->up = tb[IF_UP] && blobmsg_get_bool(tb[IF_UP]);
	i->ifindex = 0;
	if (tb[IF_L3DEV]) {
		i->device = strdup(blobmsg_get_string(tb[IF_L3DEV]));
		i->ifindex = if_nametoindex(i->device);
	}

	i->avl.key = i->name;
	avl_insert(&ifaces, &i->avl);
}

static void dump_data_cb(struct ubus_request *req, int type,
			 struct blob_attr *msg)
{
	static const struct blobmsg_policy p = { .name = "interface",
						 .type = BLOBMSG_TYPE_ARRAY };
	struct blob_attr *list, *cur;
	struct avl_tree old;
	struct iface *i, *tmp;
	size_t rem;

	blobmsg_parse(&p, 1, &list, blob_data(msg), blob_len(msg));
	if (!list)
		return;

	/* move the current set aside, rebuild, then drop what disappeared */
	avl_init(&old, iface_cmp, false, NULL);
	avl_for_each_element_safe(&ifaces, i, avl, tmp)
	{
		avl_delete(&ifaces, &i->avl);
		avl_insert(&old, &i->avl);
	}

	blobmsg_for_each_attr(cur, list, rem) parse_iface(cur, &old);

	avl_for_each_element_safe(&old, i, avl, tmp)
	{
		avl_delete(&old, &i->avl);
		/* not in ifaces any more, so mdns_sync() won't see it */
		mdns_leave(i);
		ndp_close(i);
		free(i->name);
		free(i->device);
		free(i->addr4);
		free(i->addr6);
		free(i);
	}

	iface_update_addrs();
	mdns_sync();
}

static void dump_complete_cb(struct ubus_request *req, int ret)
{
	dump_pending = false;

	if (ret)
		log_warn("network.interface dump failed: %s",
			 ubus_strerror(ret));

	if (dump_again) {
		dump_again = false;
		iface_refresh();
	}
}

static void refresh_cb(struct uloop_timeout *t)
{
	uint32_t id;

	if (!ubus)
		return;

	if (dump_pending) {
		dump_again = true;
		return;
	}

	if (ubus_lookup_id(ubus, "network.interface", &id)) {
		/* netifd not up yet: try again */
		uloop_timeout_set(&refresh_timer, 1000);
		return;
	}

	if (ubus_invoke_async(ubus, id, "dump", NULL, &dump_req))
		return;

	dump_req.data_cb = dump_data_cb;
	dump_req.complete_cb = dump_complete_cb;
	dump_pending = true;
	ubus_complete_request_async(ubus, &dump_req);
}

/* debounced: netifd sends bursts of events */
void iface_refresh(void)
{
	uloop_timeout_set(&refresh_timer, 100);
}

void iface_init(void)
{
	avl_init(&ifaces, iface_cmp, false, NULL);
	refresh_timer.cb = refresh_cb;
	addr_timer.cb = addr_timer_cb;
	uloop_timeout_set(&addr_timer, 30 * 1000);
}

struct iface *iface_by_ifindex(int ifindex)
{
	struct iface *i;

	avl_for_each_element(&ifaces, i,
			     avl) if (i->ifindex == ifindex) return i;
	return NULL;
}

struct iface *iface_by_name(const char *name)
{
	struct iface *i;

	return avl_find_element(&ifaces, name, i, avl);
}

/* inside any of our stand-in prefixes? */
bool iface_addr_is_standin(const struct in6_addr *a)
{
	struct iface *i;

	avl_for_each_element(&ifaces, i, avl)
	{
		struct in6_addr p;

		if (!i->has_ula)
			continue;
		iface_standin_prefix(i, &p);
		if (!memcmp(&p, a, 12))
			return true;
	}
	return false;
}
