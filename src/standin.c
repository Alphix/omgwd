// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "omgwd.h"
#ifdef OMGWD_BPF
#include <sys/ioctl.h>
#include "bpf/xlat_cfg.h"
#endif

enum backend { BACKEND_NONE, BACKEND_IPXLAT, BACKEND_BPF };

static const char *backend_name(enum backend b)
{
	return b == BACKEND_IPXLAT ? "ipxlat" :
	       b == BACKEND_BPF	   ? "bpf" :
				     "none";
}

static enum backend backend;
static bool backend_probed, ipxlat_available;
static struct uloop_timeout sync_timer;
static bool warned_proxy_ndp;

/* routes and proxy entries we installed, to remove what is no longer wanted */
struct entry {
	struct list_head list;
	int kind; /* 4/6: route, 'p': proxy entry */
	uint8_t addr[16];
	int plen;
	int ifindex;
	bool wanted;
};

static LIST_HEAD(entries);

/* ---- helpers ------------------------------------------------------------------ */

static void pool_addr(int n, struct in_addr *out)
{
	*out = config.pool4;
	out->s_addr = htonl(ntohl(out->s_addr) + n);
}

static void embed(const struct in6_addr *prefix, struct in_addr v4,
		  struct in6_addr *out)
{
	*out = *prefix;
	memcpy(&out->s6_addr[12], &v4, 4);
}

/* the hairpin pool address in IPv6: <SI of the first client network>::<pool .1> */
static bool hairpin_pool6(struct in6_addr *out)
{
	struct iface *i;
	struct in_addr p4;

	avl_for_each_element(&ifaces, i, avl) if (i->standins)
	{
		struct in6_addr si;

		iface_standin_prefix(i, &si);
		pool_addr(1, &p4);
		embed(&si, p4, out);
		return true;
	}
	return false;
}

static bool is_client_network(const struct iface *i)
{
	struct link *l;

	if (!i->up || !i->ifindex || !i->has_ula)
		return false;
	list_for_each_entry(l, &config.links, list)
		for (size_t k = 0; k < l->n_to; k++)
			if (!strcmp(l->to[k], i->name))
				return true;
	return false;
}

static bool probe_ipxlat(void)
{
	struct nl_ipxlat xl = { .prefix6_len = 96 };
	struct in6_addr test;
	int idx, ret;

	if (nl_dummy_up(XLAT_DEV))
		return false;
	idx = if_nametoindex(XLAT_DEV);
	/* a documentation prefix nobody routes (bits 64-71 zero, as RFC 6052 requires) */
	inet_pton(AF_INET6, "2001:db8:ffff:ffff::", &test);
	xl.prefix6 = test;
	ret = nl_route(true, AF_INET6, &test, 96, idx, &xl);
	if (!ret)
		nl_route(false, AF_INET6, &test, 96, idx, NULL);
	else
		log_info("ipxlat with xmit mode not available (%s)",
			 strerror(-ret));
	return !ret;
}

/* ---- the set of routes / proxy entries ------------------------------------------ */

static void want(int kind, const void *addr, int plen, int ifindex,
		 const struct nl_ipxlat *xl)
{
	struct entry *e;
	int ret;

	list_for_each_entry(e, &entries, list)
		if (e->kind == kind && e->plen == plen &&
		    e->ifindex == ifindex &&
		    !memcmp(e->addr, addr, kind == 4 ? 4 : 16)) {
			e->wanted = true;
			if (kind == 'p')
				return; /* re-assert below anyway (netifd may flush) */
			goto apply;
		}

	e = calloc(1, sizeof(*e));
	if (!e)
		return;
	e->kind = kind;
	memcpy(e->addr, addr, kind == 4 ? 4 : 16);
	e->plen = plen;
	e->ifindex = ifindex;
	e->wanted = true;
	list_add_tail(&e->list, &entries);
apply:
	if (kind == 'p')
		ret = nl_neigh_proxy(true, (const struct in6_addr *)addr,
				     ifindex);
	else
		ret = nl_route(true, kind == 4 ? AF_INET : AF_INET6, addr, plen,
			       ifindex, xl);
	if (ret) {
		char buf[INET6_ADDRSTRLEN];

		log_warn("cannot add %s %s/%d: %s",
			 kind == 'p' ? "proxy entry" : "route",
			 inet_ntop(kind == 4 ? AF_INET : AF_INET6, addr, buf,
				   sizeof(buf)),
			 plen, strerror(-ret));
	}
}

static void unwant_all(void)
{
	struct entry *e;

	list_for_each_entry(e, &entries, list)
		e->wanted = false;
}

static void remove_unwanted(void)
{
	struct entry *e, *tmp;

	list_for_each_entry_safe(e, tmp, &entries, list) {
		if (e->wanted)
			continue;
		if (e->kind == 'p')
			nl_neigh_proxy(false, (struct in6_addr *)e->addr,
				       e->ifindex);
		else
			nl_route(false, e->kind == 4 ? AF_INET : AF_INET6,
				 e->addr, e->plen, e->ifindex, NULL);
		list_del(&e->list);
		free(e);
	}
}

/* ---- nftables -------------------------------------------------------------------- */

static void add_device(const char *net, const struct in6_addr *standin,
		       void *priv)
{
	struct in_addr v4;
	char a[INET_ADDRSTRLEN];
	FILE *f = priv;

	memcpy(&v4, &standin->s6_addr[12], 4);
	/* nft rejects a trailing comma: separator before every element but the first */
	fprintf(f, "%s%s", ftell(f) ? ", " : "",
		inet_ntop(AF_INET, &v4, a, sizeof(a)));
}

/*
 * nft -f - without a shell (the jail has none): the script on stdin, its
 * messages collected for the log. 0 on success.
 */
static int run_nft(const char *script)
{
	static const char *const paths[] = { "/usr/sbin/nft", "/sbin/nft",
					     "/usr/bin/nft" };
	int in[2], out[2], status = -1;
	char msg[4096];
	size_t n = 0;
	ssize_t r;
	pid_t pid;

	if (pipe2(in, O_CLOEXEC))
		return -1;
	if (pipe2(out, O_CLOEXEC)) {
		close(in[0]);
		close(in[1]);
		return -1;
	}
	pid = fork();
	if (pid == 0) {
		dup2(in[0], 0);
		dup2(out[1], 1);
		dup2(out[1], 2);
		for (size_t i = 0; i < ARRAY_SIZE(paths); i++)
			execl(paths[i], "nft", "-f", "-", (char *)NULL);
		_exit(127);
	}
	close(in[0]);
	close(out[1]);
	if (pid > 0) {
		for (size_t len = strlen(script), o = 0; o < len; o += r) {
			r = write(in[1], script + o, len - o);
			if (r < 0 && errno == EINTR)
				r = 0;
			else if (r < 0)
				break;
		}
	}
	close(in[1]);
	while (pid > 0 &&
	       (r = read(out[0], msg + n, sizeof(msg) - 1 - n)) != 0) {
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0)
			break;
		n += r;
		if (n == sizeof(msg) - 1)
			break;
	}
	msg[n] = 0;
	close(out[0]);
	while (pid > 0 && waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;

	if (pid > 0 && WIFSIGNALED(status)) {
		/* SIGSYS: a syscall missing from the seccomp filter (nft inherits it) */
		log_warn("nft killed by signal %d (%s)", WTERMSIG(status),
			 strsignal(WTERMSIG(status)));
		return -1;
	}
	if (pid < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) {
		log_warn("nft failed (%d): %s\nfor:\n%s",
			 pid > 0 && WIFEXITED(status) ? WEXITSTATUS(status) :
							-1,
			 msg, script);
		return -1;
	}
	log_debug("nft ruleset:\n%s", script);
	return 0;
}

static int nft_apply(bool active)
{
	char *script = NULL, a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];
	size_t size = 0;
	struct in6_addr hp6;
	struct in_addr p4;
	struct iface *i;
	FILE *f;
	int ret;

	f = open_memstream(&script, &size);
	if (!f)
		return -1;

	/* atomic replace: create (if missing), delete, define */
	fprintf(f, "table ip6 omgwd\ndelete table ip6 omgwd\n");
	fprintf(f, "table ip omgwd\ndelete table ip omgwd\n");

	if (active) {
		fprintf(f,
			"table ip6 omgwd {\n"
			"\tchain standin_snat {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n");
		avl_for_each_element(&ifaces, i, avl)
		{
			struct in6_addr si, s6;

			if (!i->standins)
				continue;
			iface_standin_prefix(i, &si);
			pool_addr(i->standins_pool, &p4);
			embed(&si, p4, &s6);
			fprintf(f,
				"\t\toifname \"%s\" ip6 daddr %s/96 snat to %s\n",
				XLAT_DEV,
				inet_ntop(AF_INET6, &si, a, sizeof(a)),
				inet_ntop(AF_INET6, &s6, b, sizeof(b)));
		}
		if (config.has_pref64 && hairpin_pool6(&hp6))
			fprintf(f,
				"\t\toifname \"%s\" ip6 daddr %s/96 snat to %s\n",
				XLAT_DEV,
				inet_ntop(AF_INET6, &config.pref64, a,
					  sizeof(a)),
				inet_ntop(AF_INET6, &hp6, b, sizeof(b)));
		fprintf(f, "\t}\n");

		if (config.ndp == NDP_SELF) {
			fprintf(f,
				"\tchain standin_ndp {\n\t\ttype filter hook prerouting priority raw; policy accept;\n");
			avl_for_each_element(&ifaces, i, avl)
			{
				struct in6_addr si;

				if (!i->standins)
					continue;
				iface_standin_prefix(i, &si);
				fprintf(f,
					"\t\tip6 daddr %s/96 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } drop\n",
					inet_ntop(AF_INET6, &si, a, sizeof(a)));
			}
			fprintf(f, "\t}\n");
		}
		fprintf(f, "}\n");

		fprintf(f,
			"table ip omgwd {\n\tset targets {\n\t\ttype ipv4_addr\n");
		{
			char *list = NULL;
			size_t lsize = 0;
			FILE *l = open_memstream(&list, &lsize);

			if (l) {
				xlat_foreach_standin(add_device, l);
				fclose(l);
				if (list && *list)
					fprintf(f, "\t\telements = { %s }\n",
						list);
				free(list);
			}
		}
		fprintf(f, "\t}\n");
		inet_ntop(AF_INET, &config.pool4, a, sizeof(a));
		fprintf(f,
			"\tchain standin_forward {\n\t\ttype filter hook forward priority filter; policy accept;\n"
			"\t\tip saddr %s/24 ip daddr != @targets drop\n\t}\n",
			a);
		fprintf(f,
			"\tchain standin_snat {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
			"\t\tip saddr %s/24 oifname != \"%s\" masquerade\n\t}\n}\n",
			a, XLAT_DEV);
	}
	fclose(f);

	ret = run_nft(script);
	free(script);
	return ret;
}

/* ---- sync ---------------------------------------------------------------------- */

struct hp_ctx {
	int idx;
	struct nl_ipxlat *xl;
};

static void want_standin(const char *net, const struct in6_addr *standin,
			 void *priv)
{
	struct iface *b = iface_by_name(net);

	/* kernel NDP: a proxy entry per advertised stand-in on its network */
	if (config.ndp == NDP_KERNEL && b && b->standins)
		want('p', standin, 128, b->ifindex, NULL);
}

static void want_hairpin(const char *net, const struct in6_addr *standin,
			 void *priv)
{
	struct hp_ctx *c = priv;
	struct in_addr v4;
	struct in6_addr dst;

	memcpy(&v4, &standin->s6_addr[12], 4);
	embed(&config.pref64, v4, &dst);
	want(6, &dst, 128, c->idx, c->xl);
}

static void check_proxy_ndp(void)
{
	FILE *f;
	int v = 0;

	if (config.ndp != NDP_KERNEL || warned_proxy_ndp)
		return;
	f = fopen("/proc/sys/net/ipv6/conf/all/proxy_ndp", "r");
	if (f) {
		if (fscanf(f, "%d", &v) != 1)
			v = 0;
		fclose(f);
	}
	if (!v) {
		log_warn(
			"ndp 'kernel': net.ipv6.conf.all.proxy_ndp is 0; unicast neighbour "
			"solicitations for stand-ins are only answered with it set, or with a "
			"kernel that honours the per-interface flag");
		warned_proxy_ndp = true;
	}
}

#ifdef OMGWD_BPF
static void bpf_unload_if_any(void)
{
	bpf_xlat_unload();
}

/* attach the program to xlat0 and write its configuration */
static void bpf_configure(int idx)
{
	struct xlat_cfg c = { 0 };
	struct ifreq ifr = { 0 };
	struct in6_addr hp6;
	struct iface *i;
	int fd;

	if (bpf_xlat_attach(idx))
		return;

	avl_for_each_element(&ifaces, i, avl)
	{
		struct in6_addr si;
		struct in_addr p4;

		if (!i->standins || c.n_si >= XLAT_MAX_SI)
			continue;
		iface_standin_prefix(i, &si);
		memcpy(c.si[c.n_si], &si, 12);
		pool_addr(i->standins_pool, &p4);
		c.pool[c.n_si] = p4.s_addr;
		c.n_si++;
	}
	if (config.has_pref64 && hairpin_pool6(&hp6)) {
		struct in_addr p4;

		c.has_p64 = 1;
		memcpy(c.p64, &config.pref64, 12);
		pool_addr(1, &p4);
		c.pool_hp = p4.s_addr;
		for (__u32 k = 0; k < c.n_si; k++)
			if (!memcmp(c.si[k], &hp6, 12))
				c.hp_si = k;
	}

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", XLAT_DEV);
	if (fd >= 0 && !ioctl(fd, SIOCGIFHWADDR, &ifr))
		memcpy(c.mac, ifr.ifr_hwaddr.sa_data, 6);
	if (fd >= 0)
		close(fd);

	if (bpf_xlat_config(&c))
		log_warn("cannot configure the BPF translation backend");
}
#else
static void bpf_unload_if_any(void)
{
}
#endif

static void sync_cb(struct uloop_timeout *t)
{
	struct iface *i;
	int n = 2, idx = 0;
	bool any = false;

	if (!backend_probed && config.xlat != XLAT_NONE) {
		ipxlat_available = probe_ipxlat();
		backend_probed = true;
	}
	backend = BACKEND_NONE;
	if (config.enabled &&
	    (config.xlat == XLAT_AUTO || config.xlat == XLAT_IPXLAT) &&
	    ipxlat_available)
		backend = BACKEND_IPXLAT;
#ifdef OMGWD_BPF
	else if (config.enabled &&
		 (config.xlat == XLAT_AUTO || config.xlat == XLAT_BPF))
		backend = BACKEND_BPF;
#endif
	else if (config.enabled && config.xlat == XLAT_IPXLAT)
		log_warn("xlat 'ipxlat' configured, but not available");
	else if (config.enabled && config.xlat == XLAT_BPF)
		log_warn("xlat 'bpf' configured, but not compiled in");

	avl_for_each_element(&ifaces, i, avl)
	{
		bool want_si = backend != BACKEND_NONE && is_client_network(i);

		if (want_si && config.ndp == NDP_SELF && i->ndp_fd.fd < 0)
			ndp_open(i);
		else if ((!want_si || config.ndp != NDP_SELF) &&
			 i->ndp_fd.fd >= 0)
			ndp_close(i);
		i->standins = want_si;
		i->standins_pool = want_si ? n++ : 0;
		any |= want_si;
	}

	unwant_all();
	if (any) {
		if (nl_dummy_up(XLAT_DEV))
			log_warn("cannot set up %s", XLAT_DEV);
		idx = if_nametoindex(XLAT_DEV);

		/* ipxlat: the routes carry the translation; BPF: plain routes */
		bool encap = backend == BACKEND_IPXLAT;

		avl_for_each_element(&ifaces, i, avl)
		{
			struct nl_ipxlat xl = { .prefix6_len = 96 };
			struct in_addr p4;

			if (!i->standins)
				continue;
			iface_standin_prefix(i, &xl.prefix6);
			pool_addr(i->standins_pool, &p4);
			want(6, &xl.prefix6, 96, idx, encap ? &xl : NULL);
			want(4, &p4, 32, idx, encap ? &xl : NULL);
		}

		if (config.has_pref64) {
			struct nl_ipxlat xl = { .prefix6 = config.pref64,
						.prefix6_len = 96,
						.has_eam = true };
			struct hp_ctx c = { .idx = idx,
					    .xl = encap ? &xl : NULL };

			pool_addr(1, &xl.eam4);
			if (hairpin_pool6(&xl.eam6)) {
				want(4, &xl.eam4, 32, idx, encap ? &xl : NULL);
				xlat_foreach_standin(want_hairpin, &c);
			}
		}
#ifdef OMGWD_BPF
		if (backend == BACKEND_BPF)
			bpf_configure(idx);
#endif
		xlat_foreach_standin(want_standin, NULL);
		check_proxy_ndp();
	}
	remove_unwanted();
	nft_apply(any);

	if (!any || backend != BACKEND_BPF)
		bpf_unload_if_any();
	if (!any && if_nametoindex(XLAT_DEV))
		nl_link_del(XLAT_DEV);
}

void standin_changed(void)
{
	uloop_timeout_set(&sync_timer, 100);
}

void standin_init(void)
{
	sync_timer.cb = sync_cb;
}

void standin_shutdown(void)
{
	struct iface *i;

	avl_for_each_element(&ifaces, i, avl) ndp_close(i);
	unwant_all();
	remove_unwanted();
	nft_apply(false);
	bpf_unload_if_any();
	nl_link_del(XLAT_DEV);
}

void standin_dump(struct blob_buf *b)
{
	void *t = blobmsg_open_table(b, "standins"), *a;
	char buf[INET6_ADDRSTRLEN];
	struct in6_addr hp6;
	struct iface *i;

	blobmsg_add_string(b, "backend", backend_name(backend));
	blobmsg_add_string(b, "ndp", ndp_mode_name(config.ndp));
	blobmsg_add_string(b, "pool4",
			   inet_ntop(AF_INET, &config.pool4, buf, sizeof(buf)));
	if (config.has_pref64)
		blobmsg_add_string(b, "pref64",
				   inet_ntop(AF_INET6, &config.pref64, buf,
					     sizeof(buf)));
	if (config.has_pref64 && hairpin_pool6(&hp6))
		blobmsg_add_string(b, "hairpin_pool",
				   inet_ntop(AF_INET6, &hp6, buf, sizeof(buf)));
	a = blobmsg_open_array(b, "networks");
	avl_for_each_element(&ifaces, i, avl)
	{
		struct in6_addr si;
		struct in_addr p4;
		void *n;

		if (!i->standins)
			continue;
		n = blobmsg_open_table(b, NULL);
		blobmsg_add_string(b, "network", i->name);
		iface_standin_prefix(i, &si);
		blobmsg_add_string(b, "prefix",
				   inet_ntop(AF_INET6, &si, buf, sizeof(buf)));
		pool_addr(i->standins_pool, &p4);
		blobmsg_add_string(b, "pool",
				   inet_ntop(AF_INET, &p4, buf, sizeof(buf)));
		blobmsg_close_table(b, n);
	}
	blobmsg_close_array(b, a);
	blobmsg_close_table(b, t);
}
