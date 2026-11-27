// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "omgwd.h"

static int send_fd = -1;

static struct sock_filter ns_filter_code[] = {
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsetof(struct ip6_hdr, ip6_nxt)),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 3),
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS,
		 sizeof(struct ip6_hdr) +
			 offsetof(struct icmp6_hdr, icmp6_type)),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_SOLICIT, 0, 1),
	BPF_STMT(BPF_RET | BPF_K, 0xffff),
	BPF_STMT(BPF_RET | BPF_K, 0),
};

static const struct sock_fprog ns_filter = {
	.len = ARRAY_SIZE(ns_filter_code),
	.filter = ns_filter_code,
};

static struct iface *iface_by_ndp_fd(struct uloop_fd *u)
{
	return container_of(u, struct iface, ndp_fd);
}

static bool link_local(const char *dev, struct in6_addr *ll)
{
	struct ifaddrs *ifa, *a;
	bool found = false;

	if (getifaddrs(&ifa))
		return false;

	for (a = ifa; a; a = a->ifa_next) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)a->ifa_addr;

		if (s && s->sin6_family == AF_INET6 &&
		    !strcmp(a->ifa_name, dev) &&
		    IN6_IS_ADDR_LINKLOCAL(&s->sin6_addr)) {
			*ll = s->sin6_addr;
			found = true;
			break;
		}
	}

	freeifaddrs(ifa);
	return found;
}

static void send_na(struct iface *i, const struct in6_addr *to,
		    const struct in6_addr *target, bool dad)
{
	struct {
		struct nd_neighbor_advert na;
		struct nd_opt_hdr opt;
		uint8_t mac[ETH_ALEN];
	} __attribute__((packed)) na = { 0 };
	struct sockaddr_in6 dst = {
		.sin6_family = AF_INET6,
		.sin6_scope_id = i->ifindex,
	};
	uint8_t cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = { 0 };
	struct iovec iov = { .iov_base = &na, .iov_len = sizeof(na) };
	struct msghdr msg = {
		.msg_name = &dst,
		.msg_namelen = sizeof(dst),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};
	struct ifreq ifr = { 0 };
	struct cmsghdr *cm = (struct cmsghdr *)cbuf;
	struct in6_pktinfo *pi;
	struct in6_addr ll;

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", i->device);
	if (ioctl(send_fd, SIOCGIFHWADDR, &ifr) < 0 ||
	    !link_local(i->device, &ll))
		return;

	na.na.nd_na_type = ND_NEIGHBOR_ADVERT;
	na.na.nd_na_flags_reserved = dad ? 0 : ND_NA_FLAG_SOLICITED;
	na.na.nd_na_target = *target;
	na.opt.nd_opt_type = ND_OPT_TARGET_LINKADDR;
	na.opt.nd_opt_len = 1;
	memcpy(na.mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	if (dad)
		inet_pton(AF_INET6, "ff02::1", &dst.sin6_addr);
	else
		dst.sin6_addr = *to;

	cm->cmsg_level = IPPROTO_IPV6;
	cm->cmsg_type = IPV6_PKTINFO;
	cm->cmsg_len = CMSG_LEN(sizeof(*pi));
	pi = (struct in6_pktinfo *)CMSG_DATA(cm);
	pi->ipi6_addr = ll;
	pi->ipi6_ifindex = i->ifindex;

	if (sendmsg(send_fd, &msg, 0) < 0)
		log_debug("%s: NA: %m", i->name);
	else
		i->tx_na++;
}

static void ns_cb(struct uloop_fd *u, unsigned int events)
{
	struct iface *i = iface_by_ndp_fd(u);
	uint8_t buf[1500];
	ssize_t n;

	while ((n = recv(u->fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
		struct nd_neighbor_solicit *ns =
			(struct nd_neighbor_solicit *)(ip6 + 1);

		if (n < (ssize_t)(sizeof(*ip6) + sizeof(*ns)) ||
		    ip6->ip6_hlim != 255 || ns->nd_ns_code != 0 ||
		    IN6_IS_ADDR_MULTICAST(&ns->nd_ns_target))
			continue;
		if (!xlat_standin_active(i->name, &ns->nd_ns_target))
			continue;
		send_na(i, &ip6->ip6_src, &ns->nd_ns_target,
			IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src));
	}
}

bool ndp_open(struct iface *i)
{
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IPV6),
		.sll_ifindex = i->ifindex,
	};
	struct packet_mreq mreq = {
		.mr_ifindex = i->ifindex,
		.mr_type = PACKET_MR_ALLMULTI,
	};
	int fd;
	int hops = 255;

	if (send_fd < 0) {
		struct icmp6_filter f;

		send_fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC,
				 IPPROTO_ICMPV6);
		if (send_fd < 0 ||
		    setsockopt(send_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops,
			       sizeof(hops)) ||
		    setsockopt(send_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			       &hops, sizeof(hops))) {
			log_err("NDP send socket: %m");
			if (send_fd >= 0) {
				close(send_fd);
				send_fd = -1;
			}
			return false;
		}
		ICMP6_FILTER_SETBLOCKALL(&f);
		setsockopt(send_fd, IPPROTO_ICMPV6, ICMP6_FILTER, &f,
			   sizeof(f));
	}

	fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    htons(ETH_P_IPV6));
	if (fd < 0)
		goto err;

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &ns_filter,
		       sizeof(ns_filter)) ||
	    bind(fd, (struct sockaddr *)&sll, sizeof(sll)) ||
	    setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq,
		       sizeof(mreq)))
		goto err;

	i->ndp_fd.fd = fd;
	i->ndp_fd.cb = ns_cb;
	uloop_fd_add(&i->ndp_fd, ULOOP_READ);
	log_debug("%s: NDP responder on %s", i->name, i->device);
	return true;

err:
	log_err("%s: NDP responder: %m", i->name);
	if (fd >= 0)
		close(fd);
	return false;
}

void ndp_close(struct iface *i)
{
	if (i->ndp_fd.fd < 0)
		return;

	uloop_fd_delete(&i->ndp_fd);
	close(i->ndp_fd.fd);
	i->ndp_fd.fd = -1;
}
