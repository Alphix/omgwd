// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include <libubus.h>

#include "omgwd.h"

struct ubus_context *ubus;

static struct ubus_auto_conn conn;
static struct blob_buf b;

/* ---- methods ----------------------------------------------------------------- */

static void dump_links(void)
{
	void *a = blobmsg_open_array(&b, "links");
	struct link *l;

	list_for_each_entry(l, &config.links, list) {
		void *t = blobmsg_open_table(&b, NULL), *x;

		blobmsg_add_string(&b, "name", l->name);
		blobmsg_add_string(&b, "from", l->from);
		x = blobmsg_open_array(&b, "to");
		for (size_t k = 0; k < l->n_to; k++)
			blobmsg_add_string(&b, NULL, l->to[k]);
		blobmsg_close_array(&b, x);
		x = blobmsg_open_array(&b, "services");
		for (size_t k = 0; k < l->n_services; k++)
			blobmsg_add_string(&b, NULL, l->services[k]);
		blobmsg_close_array(&b, x);
		blobmsg_close_table(&b, t);
	}
	blobmsg_close_array(&b, a);
}

static void dump_networks(void)
{
	void *a = blobmsg_open_array(&b, "networks");
	char buf[INET6_ADDRSTRLEN + 4];
	struct iface *i;

	avl_for_each_element(&ifaces, i, avl)
	{
		void *t = blobmsg_open_table(&b, NULL), *c;

		blobmsg_add_string(&b, "name", i->name);
		if (i->device)
			blobmsg_add_string(&b, "device", i->device);
		blobmsg_add_u32(&b, "ifindex", i->ifindex);
		blobmsg_add_u8(&b, "up", i->up);
		blobmsg_add_u8(&b, "mdns_ipv4", i->joined4);
		blobmsg_add_u8(&b, "mdns_ipv6", i->joined6);
		if (i->has_ula) {
			struct in6_addr p;

			inet_ntop(AF_INET6, &i->ula64, buf, sizeof(buf));
			strcat(buf, "/64");
			blobmsg_add_string(&b, "ula", buf);
			iface_standin_prefix(i, &p);
			inet_ntop(AF_INET6, &p, buf, sizeof(buf));
			strcat(buf, "/96");
			blobmsg_add_string(&b, "standin_prefix", buf);
		}

		c = blobmsg_open_table(&b, "counters");
		blobmsg_add_u64(&b, "rx_ipv4", i->rx4);
		blobmsg_add_u64(&b, "rx_ipv6", i->rx6);
		blobmsg_add_u64(&b, "rx_queries", i->rx_queries);
		blobmsg_add_u64(&b, "rx_responses", i->rx_responses);
		blobmsg_add_u64(&b, "rx_invalid", i->rx_bad);
		blobmsg_add_u64(&b, "rx_own", i->rx_own);
		blobmsg_add_u64(&b, "rx_loop", i->rx_loop);
		blobmsg_add_u64(&b, "tx_repeated", i->tx_repeated);
		blobmsg_add_u64(&b, "tx_translated", i->tx_translated);
		blobmsg_add_u64(&b, "tx_answered", i->tx_answered);
		blobmsg_add_u64(&b, "tx_na", i->tx_na);
		blobmsg_close_table(&b, c);

		blobmsg_close_table(&b, t);
	}
	blobmsg_close_array(&b, a);
}

static int handle_status(struct ubus_context *ctx, struct ubus_object *obj,
			 struct ubus_request_data *req, const char *method,
			 struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "version", OMGWD_VERSION);
	blobmsg_add_u8(&b, "enabled", config.enabled);
	blobmsg_add_string(&b, "ndp", ndp_mode_name(config.ndp));
	blobmsg_add_string(&b, "xlat", xlat_mode_name(config.xlat));
	blobmsg_add_u8(&b, "answer_from_state", config.answer_from_state);
	overrides_dump(&b);
	dump_links();
	dump_networks();
	mdns_dump(&b);
	standin_dump(&b);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}

static int handle_reload(struct ubus_context *ctx, struct ubus_object *obj,
			 struct ubus_request_data *req, const char *method,
			 struct blob_attr *msg)
{
	if (!config_load())
		return UBUS_STATUS_INVALID_ARGUMENT;
	iface_refresh();
	standin_changed();
	return 0;
}

/* what we see and what we do with it, per instance */
static int handle_devices(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	xlat_dump(&b);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}

/* the raw state */
static int handle_records(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	state_dump_records(&b);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}

static const struct ubus_method methods[] = {
	UBUS_METHOD_NOARG("status", handle_status),
	UBUS_METHOD_NOARG("devices", handle_devices),
	UBUS_METHOD_NOARG("records", handle_records),
	UBUS_METHOD_NOARG("reload", handle_reload),
};

static struct ubus_object_type object_type = UBUS_OBJECT_TYPE("omgwd", methods);

static struct ubus_object object = {
	.name = "omgwd",
	.type = &object_type,
	.methods = methods,
	.n_methods = ARRAY_SIZE(methods),
};

/* ---- events ------------------------------------------------------------------ */

/*
 * netifd's network.interface ubus event only reports ifup/ifdown; updates are
 * notifications to subscribers of the network.interface object.
 */
static struct ubus_subscriber netifd_sub;

static int netifd_notify_cb(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method,
			    struct blob_attr *msg)
{
	iface_refresh();
	return 0;
}

static void netifd_subscribe(void)
{
	uint32_t id;
	int ret;

	if (!ubus || ubus_lookup_id(ubus, "network.interface", &id))
		return; /* subscribed when the object appears */

	ret = ubus_subscribe(ubus, &netifd_sub, id);
	if (ret)
		log_warn("cannot subscribe to network.interface: %s",
			 ubus_strerror(ret));
}

/* netifd (re)started */
static void object_add_cb(struct ubus_context *ctx,
			  struct ubus_event_handler *ev, const char *type,
			  struct blob_attr *msg)
{
	static const struct blobmsg_policy p = { .name = "path",
						 .type = BLOBMSG_TYPE_STRING };
	struct blob_attr *path;

	blobmsg_parse(&p, 1, &path, blob_data(msg), blob_len(msg));
	if (path && !strcmp(blobmsg_get_string(path), "network.interface")) {
		netifd_subscribe();
		iface_refresh();
	}
}

static struct ubus_event_handler object_add_event = { .cb = object_add_cb };

static void connect_cb(struct ubus_context *ctx)
{
	ubus = ctx;

	if (ubus_add_object(ctx, &object))
		log_err("cannot register the ubus object");

	netifd_sub.cb = netifd_notify_cb;
	if (ubus_register_subscriber(ctx, &netifd_sub))
		log_err("cannot register the netifd subscriber");
	netifd_subscribe();
	ubus_register_event_handler(ctx, &object_add_event, "ubus.object.add");

	log_info("connected to ubus");
	iface_refresh();
}

void ubus_init(void)
{
	conn.cb = connect_cb;
	conn.path = ubus_socket;
	ubus_auto_connect(&conn);
}
