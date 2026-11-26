// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "omgwd.h"
#include "dns/dns.h"

static struct uloop_fd sock4 = { .fd = -1 };
static struct uloop_fd sock6 = { .fd = -1 };

/* the socket filter sees the UDP header at offset 0 */
static struct sock_filter mdns_filter_code[] = {
	BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
	BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 8 + DNS_HDR_LEN, 1, 0),
	BPF_STMT(BPF_RET | BPF_K, 0), /* too short */
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 8 + 2), /* QR|opcode|AA|TC|RD */
	BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x78),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
	BPF_STMT(BPF_RET | BPF_K, 0xffffffff), /* opcode QUERY */
	BPF_STMT(BPF_RET | BPF_K, 0),
};

static const struct sock_fprog mdns_filter = {
	.len = ARRAY_SIZE(mdns_filter_code),
	.filter = mdns_filter_code,
};

/* ---- recently sent packets ------------------------------------------------ */

#define SENT_SLOTS 128
#define SENT_TTL_MS 2000

static struct {
	uint64_t hash;
	int64_t when;
	int ifindex;
	int family;
} sent[SENT_SLOTS];
static unsigned int sent_next;

static uint64_t fnv1a(const uint8_t *buf, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ULL;

	for (size_t i = 0; i < len; i++) {
		h ^= buf[i];
		h *= 0x100000001b3ULL;
	}
	return h;
}

static void sent_remember(int ifindex, int family, const uint8_t *buf,
			  size_t len)
{
	sent[sent_next].hash = fnv1a(buf, len);
	sent[sent_next].when = now_ms();
	sent[sent_next].ifindex = ifindex;
	sent[sent_next].family = family;
	sent_next = (sent_next + 1) % SENT_SLOTS;
}

static bool sent_recently(int ifindex, int family, const uint8_t *buf,
			  size_t len)
{
	uint64_t h = fnv1a(buf, len);
	int64_t now = now_ms();

	for (unsigned int k = 0; k < SENT_SLOTS; k++)
		if (sent[k].when && now - sent[k].when < SENT_TTL_MS &&
		    sent[k].hash == h && sent[k].ifindex == ifindex &&
		    sent[k].family == family)
			return true;
	return false;
}

/* ---- receiving ------------------------------------------------------------ */

static void handle_packet(struct iface *i, int family, const void *src,
			  const uint8_t *buf, size_t len)
{
	struct dns_msg m;
	char sbuf[INET6_ADDRSTRLEN];

	if (iface_is_own_addr(i, family, src)) {
		i->rx_own++;
		return;
	}
	if (sent_recently(i->ifindex, family, buf, len)) {
		i->rx_loop++;
		return;
	}

	if (family == AF_INET)
		i->rx4++;
	else
		i->rx6++;

	if (wire_parse(buf, len, &m, false)) {
		i->rx_bad++;
		return;
	}

	if (m.flags & DNS_F_QR)
		i->rx_responses++;
	else
		i->rx_queries++;

	log_debug("%s: %s from %s, %zu question(s), %zu/%zu/%zu records",
		  i->name, (m.flags & DNS_F_QR) ? "response" : "query",
		  inet_ntop(family, src, sbuf, sizeof(sbuf)), m.n_qd, m.an.n,
		  m.ns.n, m.ar.n);

	/* the state first: translation looks up instances and native IPv6 there */
	state_update(i, family, &m);
	repeat_packet(i, family, buf, len, &m);
	xlat_packet(i, family, &m);
	answer_query(i, family, &m);
	if (m.flags & DNS_F_QR)
		xlat_state_changed();
	dns_msg_free(&m);
}

static void recv_cb(struct uloop_fd *u, unsigned int events)
{
	int family = u == &sock4 ? AF_INET : AF_INET6;

	while (true) {
		uint8_t buf[9000];
		union {
			struct sockaddr_in in;
			struct sockaddr_in6 in6;
		} from;
		uint8_t cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
			     CMSG_SPACE(sizeof(struct in_pktinfo))];
		struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
		struct msghdr msg = {
			.msg_name = &from,
			.msg_namelen = sizeof(from),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cbuf,
			.msg_controllen = sizeof(cbuf),
		};
		struct cmsghdr *cm;
		struct iface *i;
		int ifindex = 0;
		bool mcast = false;
		uint16_t sport;
		ssize_t n;

		n = recvmsg(u->fd, &msg, MSG_DONTWAIT);
		if (n < 0) {
			if (errno != EAGAIN && errno != EINTR)
				log_warn("recvmsg: %s", strerror(errno));
			return;
		}

		for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
			if (cm->cmsg_level == IPPROTO_IP &&
			    cm->cmsg_type == IP_PKTINFO) {
				struct in_pktinfo *pi =
					(struct in_pktinfo *)CMSG_DATA(cm);

				ifindex = pi->ipi_ifindex;
				mcast = IN_MULTICAST(
					ntohl(pi->ipi_addr.s_addr));
			} else if (cm->cmsg_level == IPPROTO_IPV6 &&
				   cm->cmsg_type == IPV6_PKTINFO) {
				struct in6_pktinfo *pi =
					(struct in6_pktinfo *)CMSG_DATA(cm);

				ifindex = pi->ipi6_ifindex;
				mcast = IN6_IS_ADDR_MULTICAST(&pi->ipi6_addr);
			}
		}

		i = ifindex ? iface_by_ifindex(ifindex) : NULL;
		if (!i || !i->up)
			continue; /* not a network we serve (or umdns' traffic elsewhere) */

		sport = family == AF_INET ? ntohs(from.in.sin_port) :
					    ntohs(from.in6.sin6_port);
		if (!mcast || sport != MDNS_PORT)
			continue; /* unicast or legacy unicast: nothing to repeat */

		handle_packet(i, family,
			      family == AF_INET ? (void *)&from.in.sin_addr :
						  (void *)&from.in6.sin6_addr,
			      buf, n);
	}
}

static int open_socket(int family)
{
	int fd, on = 1, hops = 255, off = 0;

	fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    IPPROTO_UDP);
	if (fd < 0)
		return -1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) ||
	    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) ||
	    setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &mdns_filter,
		       sizeof(mdns_filter)))
		goto err;

	if (family == AF_INET) {
		struct sockaddr_in sin = { .sin_family = AF_INET,
					   .sin_port = htons(MDNS_PORT) };
		unsigned char ttl = 255, loop = 0;

		if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) ||
		    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
			       sizeof(ttl)) ||
		    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop,
			       sizeof(loop)) ||
		    bind(fd, (struct sockaddr *)&sin, sizeof(sin)))
			goto err;
	} else {
		struct sockaddr_in6 sin6 = { .sin6_family = AF_INET6,
					     .sin6_port = htons(MDNS_PORT) };

		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on,
			       sizeof(on)) ||
		    setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
			       sizeof(on)) ||
		    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
			       sizeof(hops)) ||
		    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &off,
			       sizeof(off)) ||
		    bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)))
			goto err;
	}
	return fd;
err:
	log_err("mDNS %s socket: %s", family == AF_INET ? "IPv4" : "IPv6",
		strerror(errno));
	close(fd);
	return -1;
}

/* ---- sending -------------------------------------------------------------- */

int mdns_send(struct iface *i, int family, const uint8_t *buf, size_t len)
{
	uint8_t cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = { 0 };
	struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
	struct msghdr msg = { .msg_iov = &iov,
			      .msg_iovlen = 1,
			      .msg_control = cbuf };
	struct sockaddr_in6 to6 = { .sin6_family = AF_INET6,
				    .sin6_port = htons(MDNS_PORT) };
	struct sockaddr_in to4 = { .sin_family = AF_INET,
				   .sin_port = htons(MDNS_PORT) };
	struct cmsghdr *cm;
	int fd;

	if (!(family == AF_INET ? i->joined4 : i->joined6) || !i->ifindex)
		return -1;

	cm = (struct cmsghdr *)cbuf;
	if (family == AF_INET) {
		struct in_pktinfo *pi;

		inet_pton(AF_INET, MDNS_ADDR4, &to4.sin_addr);
		msg.msg_name = &to4;
		msg.msg_namelen = sizeof(to4);
		msg.msg_controllen = CMSG_SPACE(sizeof(*pi));
		cm->cmsg_level = IPPROTO_IP;
		cm->cmsg_type = IP_PKTINFO;
		cm->cmsg_len = CMSG_LEN(sizeof(*pi));
		pi = (struct in_pktinfo *)CMSG_DATA(cm);
		pi->ipi_ifindex = i->ifindex;
		fd = sock4.fd;
	} else {
		struct in6_pktinfo *pi;

		inet_pton(AF_INET6, MDNS_ADDR6, &to6.sin6_addr);
		to6.sin6_scope_id = i->ifindex;
		msg.msg_name = &to6;
		msg.msg_namelen = sizeof(to6);
		msg.msg_controllen = CMSG_SPACE(sizeof(*pi));
		cm->cmsg_level = IPPROTO_IPV6;
		cm->cmsg_type = IPV6_PKTINFO;
		cm->cmsg_len = CMSG_LEN(sizeof(*pi));
		pi = (struct in6_pktinfo *)CMSG_DATA(cm);
		pi->ipi6_ifindex = i->ifindex;
		fd = sock6.fd;
	}

	if (sendmsg(fd, &msg, 0) < 0) {
		log_debug("%s: send: %s", i->name, strerror(errno));
		return -1;
	}
	sent_remember(i->ifindex, family, buf, len);
	return 0;
}

int mdns_init(void)
{
	sock4.fd = open_socket(AF_INET);
	sock6.fd = open_socket(AF_INET6);
	if (sock4.fd < 0 || sock6.fd < 0)
		return -1;

	sock4.cb = sock6.cb = recv_cb;
	uloop_fd_add(&sock4, ULOOP_READ);
	uloop_fd_add(&sock6, ULOOP_READ);
	return 0;
}

static bool membership(struct iface *i, int family, bool join)
{
	int ifindex = join ? i->ifindex : i->joined_ifindex;
	int ret;

	if (family == AF_INET) {
		struct ip_mreqn mr = { .imr_ifindex = ifindex };

		inet_pton(AF_INET, MDNS_ADDR4, &mr.imr_multiaddr);
		ret = setsockopt(sock4.fd, IPPROTO_IP,
				 join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP,
				 &mr, sizeof(mr));
	} else {
		struct ipv6_mreq mr = { .ipv6mr_interface = ifindex };

		inet_pton(AF_INET6, MDNS_ADDR6, &mr.ipv6mr_multiaddr);
		ret = setsockopt(sock6.fd, IPPROTO_IPV6,
				 join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, &mr,
				 sizeof(mr));
	}

	/* already a member, e.g. after a restart of the network: fine */
	if (ret && join && errno == EADDRINUSE)
		ret = 0;
	if (ret && join)
		log_warn("%s: cannot join the %s mDNS group: %s", i->name,
			 family == AF_INET ? "IPv4" : "IPv6", strerror(errno));
	return !ret;
}

void mdns_leave(struct iface *i)
{
	if (i->joined4)
		membership(i, AF_INET, false);
	if (i->joined6)
		membership(i, AF_INET6, false);
	i->joined4 = i->joined6 = false;
}

/* join the groups on every network that is up (and leave where it went down) */
void mdns_sync(void)
{
	struct iface *i;

	standin_changed(); /* networks changed: client networks, routes */

	avl_for_each_element(&ifaces, i, avl)
	{
		bool want = config.enabled && i->up && i->ifindex;

		if (!want) {
			mdns_leave(i);
			continue;
		}
		/* the device may have changed (ifindex): rejoin to be sure */
		mdns_leave(i);
		i->joined4 = membership(i, AF_INET, true);
		i->joined6 = membership(i, AF_INET6, true);
		i->joined_ifindex = i->ifindex;
		log_debug("%s: %s (ifindex %d), mDNS groups %s/%s", i->name,
			  i->device, i->ifindex, i->joined4 ? "v4" : "-",
			  i->joined6 ? "v6" : "-");
	}
}

void mdns_dump(struct blob_buf *b)
{
	void *t = blobmsg_open_table(b, "sockets");

	blobmsg_add_u8(b, "ipv4", sock4.fd >= 0);
	blobmsg_add_u8(b, "ipv6", sock6.fd >= 0);
	blobmsg_close_table(b, t);
}
