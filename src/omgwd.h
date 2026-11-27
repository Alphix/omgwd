/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu> */

#ifndef OMGWD_H
#define OMGWD_H

#include <stdint.h>
#include <netinet/in.h>
#include <syslog.h>

#include <libubox/avl.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/ulog.h>

#include "dns/dns.h"

#define OMGWD_VERSION "0.1"

#define MDNS_PORT 5353
#define MDNS_ADDR4 "224.0.0.251"
#define MDNS_ADDR6 "ff02::fb"

extern int debug_level;

int64_t now_ms(void);
extern const char *uci_confdir;
extern const char *ubus_socket;

#define log_err(fmt, ...) ulog(LOG_ERR, fmt "\n", ##__VA_ARGS__)
#define log_warn(fmt, ...) ulog(LOG_WARNING, fmt "\n", ##__VA_ARGS__)
#define log_info(fmt, ...) ulog(LOG_INFO, fmt "\n", ##__VA_ARGS__)
#define log_debug(fmt, ...)                                       \
	do {                                                      \
		if (debug_level)                                  \
			ulog(LOG_DEBUG, fmt "\n", ##__VA_ARGS__); \
	} while (0)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

/*
 * An address record that only means something on its own link: AAAA in
 * fe80::/10 or A in 169.254.0.0/16 (RFC 8766 5.5.2 suppresses them off-link;
 * routers don't forward to them).
 */
static inline bool rr_link_local_addr(const struct dns_rr *rr)
{
	if (rr->type == DNS_T_AAAA && rr->rdlen == 16)
		return rr->rdata[0] == 0xfe && (rr->rdata[1] & 0xc0) == 0x80;
	if (rr->type == DNS_T_A && rr->rdlen == 4)
		return rr->rdata[0] == 169 && rr->rdata[1] == 254;
	return false;
}

/* ---- configuration (config.c) ----------------------------------------- */

enum ndp_mode {
	NDP_SELF, /* our own NS responder (default) */
	NDP_KERNEL, /* kernel proxy entries; undocumented, for testing */
};

enum xlat_mode {
	XLAT_AUTO,
	XLAT_IPXLAT,
	XLAT_BPF,
	XLAT_NONE,
};

/* "services on 'from' are visible to clients on each of 'to'" */
struct link {
	struct list_head list;
	char *name; /* UCI section name */
	char *from;
	char **to;
	size_t n_to;
	char **services; /* empty: all */
	size_t n_services;
	uint8_t (*svc_names)[DNAME_MAX +
			     1]; /* "<service>.local" in wire format */
};

/* per-device quirks (override.c) */
enum ov_value {
	OV_UNSET, /* in a section: not set; never in a result */
	OV_AUTO, /* the built-in behaviour */
	OV_ON, /* always / yes / keep */
	OV_OFF, /* never / no / drop */
};

enum ov_knob {
	OV_TRANSLATE, /* translate this instance */
	OV_NATIVE, /* treat it as natively IPv6 (for translate auto) */
	OV_STANDIN, /* advertise a stand-in AAAA */
	OV_LINKLOCAL, /* keep link-local address records when repeating */
	OV_REPEAT, /* repeat its records to other networks */
	OV_KNOBS
};

/* what a decision is about; unknown parts are NULL */
struct ov_subject {
	const char *network; /* where the device lives */
	const uint8_t *instance; /* service instance */
	const uint8_t *host; /* SRV target */
};

struct ov_result {
	enum ov_value v[OV_KNOBS];
};

struct config {
	bool enabled;
	bool answer_from_state;
	enum ndp_mode ndp;
	enum xlat_mode xlat;
	struct in_addr pool4; /* SNAT pool for stand-in traffic, a /24 */
	bool has_pref64; /* local hairpin for <PREF64>::<device> */
	struct in6_addr pref64; /* /96 */
	struct list_head links;
	struct list_head overrides;
};

extern struct config config;

bool config_load(void);
void config_free(struct config *c);
bool config_uses_network(const char *name);
bool link_allows(const struct link *l, const uint8_t *name);

struct uci_section;
extern const char *quirk_dir;
bool overrides_parse_section(struct uci_section *s, struct list_head *out);
void overrides_load_quirks(struct list_head *out);
void overrides_free(struct list_head *l);
void override_eval(const struct ov_subject *s, struct ov_result *r);
bool override_sets(enum ov_knob k);
void overrides_dump(struct blob_buf *b);
const char *ov_knob_name(enum ov_knob k);
const char *ndp_mode_name(enum ndp_mode m);
const char *xlat_mode_name(enum xlat_mode m);

/* ---- networks as reported by netifd (iface.c) ----------------------------- */

struct iface {
	struct avl_node avl; /* key: logical name */
	char *name;
	char *device; /* l3 device */
	int ifindex;
	bool up;

	bool has_ula; /* stand-ins need a ULA /64 on client networks */
	struct in6_addr ula64; /* first 64 bits significant */

	/* this host's addresses on the device (own-packet detection) */
	struct in_addr *addr4;
	size_t n_addr4;
	struct in6_addr *addr6;
	size_t n_addr6;

	struct uloop_fd
		ndp_fd; /* our NS responder (ndp self) on client networks */
	bool standins; /* stand-ins are set up for this network */
	int standins_pool; /* its SNAT pool address: <pool4>.<n> */

	bool joined4, joined6; /* multicast group membership ... */
	int joined_ifindex; /* ... on this device (ifindex changes when it goes down) */

	/* counters */
	uint64_t rx4, rx6, rx_bad;
	uint64_t rx_queries, rx_responses;
	uint64_t rx_own; /* from one of our addresses (e.g. umdns) */
	uint64_t rx_loop; /* identical to what we just sent on this network */
	uint64_t tx_repeated; /* repeated onto this network */
	uint64_t tx_translated; /* sent onto this network in the other family */
	uint64_t tx_answered; /* answers from the state sent on this network */
	uint64_t tx_na; /* neighbour advertisements for stand-ins */
};

extern struct avl_tree ifaces;

void iface_init(void);
void iface_refresh(void);
struct iface *iface_by_ifindex(int ifindex);
struct iface *iface_by_name(const char *name);
bool iface_is_own_addr(const struct iface *i, int family, const void *addr);
void iface_standin_prefix(const struct iface *i, struct in6_addr *out);
bool iface_addr_is_standin(const struct in6_addr *a);

/* ---- mDNS sockets (mdns.c) ----------------------------------------------- */

bool mdns_init(void);
void mdns_sync(void);
void mdns_leave(struct iface *i);
bool mdns_send(struct iface *i, int family, const uint8_t *buf, size_t len);

/* ---- repeating within one address family (repeat.c) ---------------------- */

void repeat_packet(struct iface *in, int family, const uint8_t *buf, size_t len,
		   const struct dns_msg *m);
void mdns_dump(struct blob_buf *b);

/* ---- state: records heard per network (state.c) --------------------------- */

#define STATE_V4 1
#define STATE_V6 2

struct state_rec {
	struct avl_node avl;
	void *key;
	char origin[32]; /* network it was heard on */
	struct dns_rr rr;
	uint8_t families; /* STATE_V4 | STATE_V6 */
	int64_t seen;
	int64_t expires;
};

void state_init(void);
void state_update(struct iface *in, int family, const struct dns_msg *m);
void state_expire(void);
struct state_rec *state_first(void);
struct state_rec *state_next(struct state_rec *r);
const uint8_t *state_srv_target(const uint8_t *instance, uint8_t *families);
bool state_instance_native_v6(const uint8_t *instance);
bool state_host_has_aaaa(const char *origin, const uint8_t *host);
void state_dump_records(struct blob_buf *b);
void dname_to_display(const uint8_t *name, char *buf, size_t len);

/* ---- translation between address families (xlat.c) ------------------------ */

void xlat_packet(struct iface *in, int family, const struct dns_msg *m);
void xlat_state_changed(void);
void xlat_dump(struct blob_buf *b);
bool xlat_pair_allows(const struct iface *a, const struct iface *b,
		      const uint8_t *name);
bool xlat_decide(const struct iface *a, const struct iface *b,
		 const uint8_t *instance, const uint8_t *host);
const uint8_t *xlat_instance_for_host(const struct iface *a,
				      const struct iface *b,
				      const uint8_t *host);
bool xlat_standin_for(const struct iface *a, const struct iface *b,
		      const uint8_t *instance, const uint8_t *host,
		      const uint8_t *v4, struct in6_addr *out);
void xlat_note_standin(const struct iface *a, const struct iface *b,
		       const uint8_t *instance, const uint8_t *host,
		       const struct in6_addr *addr, uint16_t class,
		       uint32_t ttl);

/* ---- answering queries from the state (answer.c) ------------------------- */

void answer_query(struct iface *in, int family, const struct dns_msg *m);
bool answer_suppress(const struct iface *b, const struct dns_rr *rr);

/* stand-ins advertised (xlat.c) */
typedef void (*standin_cb)(const char *net, const struct in6_addr *standin,
			   void *priv);
void xlat_foreach_standin(standin_cb cb, void *priv);
bool xlat_standin_active(const char *net, const struct in6_addr *addr);

/* ---- rtnetlink (nl.c) ------------------------------------------------------- */

struct nl_ipxlat {
	struct in6_addr prefix6;
	uint8_t prefix6_len;
	bool has_eam;
	struct in_addr eam4; /* /32 */
	struct in6_addr eam6; /* /128 */
};

int nl_dummy_up(const char *name);
int nl_link_del(const char *name);
int nl_route(bool add, int family, const void *dst, int plen, int ifindex,
	     const struct nl_ipxlat *xl);
int nl_neigh_proxy(bool add, const struct in6_addr *addr, int ifindex);

/* ---- stand-ins: data plane and NDP (standin.c, ndp.c) ---------------------- */

#define XLAT_DEV "xlat0"

void standin_init(void);
void standin_changed(void); /* debounced resync */
void standin_shutdown(void);
void standin_dump(struct blob_buf *b);

/* BPF translation backend (bpf/loader.c, only with OMGWD_BPF) */
struct xlat_cfg;
int bpf_xlat_attach(int ifindex);
int bpf_xlat_config(const struct xlat_cfg *cfg);
void bpf_xlat_unload(void);

bool ndp_open(struct iface *i);
void ndp_close(struct iface *i);

/* ---- ubus (ubus.c) --------------------------------------------------------- */

extern struct ubus_context *ubus;

void ubus_init(void);

#endif
