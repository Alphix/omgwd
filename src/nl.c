// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <errno.h>
#include <linux/if_link.h>
#include <linux/lwtunnel.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "omgwd.h"
#include "ipxlat_compat.h"

struct nlreq {
	struct nlmsghdr nh;
	union {
		struct rtmsg rt;
		struct ifinfomsg ifi;
		struct ndmsg nd;
	};
	char buf[1024];
};

static int nl_fd = -1;
static uint32_t nl_seq;

static struct rtattr *rta_add(struct nlmsghdr *nh, int type, const void *data,
			      int len)
{
	struct rtattr *rta =
		(struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	if (len)
		memcpy(RTA_DATA(rta), data, len);
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
	return rta;
}

static struct rtattr *nest_start(struct nlmsghdr *nh, int type)
{
	return rta_add(nh, type | NLA_F_NESTED, NULL, 0);
}

static void nest_end(struct nlmsghdr *nh, struct rtattr *nest)
{
	nest->rta_len = (char *)nh + nh->nlmsg_len - (char *)nest;
}

/* send, wait for the ack; returns 0 or -errno */
static int nl_talk(struct nlreq *r)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	char ack[4096];
	ssize_t n;

	if (nl_fd < 0) {
		nl_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
			       NETLINK_ROUTE);
		if (nl_fd < 0)
			return -errno;
	}

	r->nh.nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;
	r->nh.nlmsg_seq = ++nl_seq;
	if (sendto(nl_fd, r, r->nh.nlmsg_len, 0, (struct sockaddr *)&sa,
		   sizeof(sa)) < 0)
		return -errno;

	while (true) {
		n = recv(nl_fd, ack, sizeof(ack), 0);
		if (n < 0)
			return -errno;
		for (struct nlmsghdr *h = (struct nlmsghdr *)ack;
		     NLMSG_OK(h, (size_t)n); h = NLMSG_NEXT(h, n)) {
			if (h->nlmsg_seq != nl_seq ||
			    h->nlmsg_type != NLMSG_ERROR)
				continue;
			return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
		}
	}
}

/* the xlat0 dummy device (created if missing), up */
int nl_dummy_up(const char *name)
{
	struct nlreq r = { 0 };
	struct rtattr *li, *data;
	int ret;

	if (!if_nametoindex(name)) {
		r.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
		r.nh.nlmsg_type = RTM_NEWLINK;
		r.nh.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;
		rta_add(&r.nh, IFLA_IFNAME, name, strlen(name) + 1);
		li = nest_start(&r.nh, IFLA_LINKINFO);
		rta_add(&r.nh, IFLA_INFO_KIND, "dummy", 5);
		data = nest_start(&r.nh, IFLA_INFO_DATA);
		nest_end(&r.nh, data);
		nest_end(&r.nh, li);
		ret = nl_talk(&r);
		if (ret && ret != -EEXIST)
			return ret;
	}

	memset(&r, 0, sizeof(r));
	r.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	r.nh.nlmsg_type = RTM_NEWLINK;
	r.ifi.ifi_index = if_nametoindex(name);
	r.ifi.ifi_flags = IFF_UP;
	r.ifi.ifi_change = IFF_UP;
	return nl_talk(&r);
}

int nl_link_del(const char *name)
{
	struct nlreq r = { 0 };

	r.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	r.nh.nlmsg_type = RTM_DELLINK;
	r.ifi.ifi_index = if_nametoindex(name);
	if (!r.ifi.ifi_index)
		return 0;
	return nl_talk(&r);
}

/*
 * route to dst/plen via dev; with xl, an ipxlat encapsulation in xmit mode
 * (rfc6052 prefix, optional EAM)
 */
int nl_route(bool add, int family, const void *dst, int plen, int ifindex,
	     const struct nl_ipxlat *xl)
{
	uint16_t etype = LWTUNNEL_ENCAP_IPXLAT;
	struct nlreq r = { 0 };
	struct rtattr *encap, *n1, *n2;

	r.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	r.nh.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
	r.nh.nlmsg_flags = add ? NLM_F_CREATE | NLM_F_REPLACE : 0;
	r.rt.rtm_family = family;
	r.rt.rtm_dst_len = plen;
	r.rt.rtm_table = RT_TABLE_MAIN;
	r.rt.rtm_protocol = RTPROT_STATIC;
	r.rt.rtm_scope = RT_SCOPE_UNIVERSE;
	r.rt.rtm_type = RTN_UNICAST;

	rta_add(&r.nh, RTA_DST, dst, family == AF_INET6 ? 16 : 4);
	rta_add(&r.nh, RTA_OIF, &ifindex, sizeof(ifindex));

	if (xl && add) {
		uint8_t len6 = xl->prefix6_len;

		rta_add(&r.nh, RTA_ENCAP_TYPE, &etype, sizeof(etype));
		encap = nest_start(&r.nh, RTA_ENCAP);
		rta_add(&r.nh, IPXLAT_A_XMIT, NULL, 0);
		n1 = nest_start(&r.nh, IPXLAT_A_RFC6052_PREFIX6);
		rta_add(&r.nh, IPXLAT_A_PREFIX6_ADDR, &xl->prefix6, 16);
		rta_add(&r.nh, IPXLAT_A_PREFIX6_LEN, &len6, 1);
		nest_end(&r.nh, n1);
		if (xl->has_eam) {
			uint8_t l4 = 32, l6 = 128;

			n1 = nest_start(&r.nh, IPXLAT_A_EAMT);
			n2 = nest_start(&r.nh, 1);
			rta_add(&r.nh, IPXLAT_A_EAM_PREFIX4, &xl->eam4, 4);
			rta_add(&r.nh, IPXLAT_A_EAM_PREFIX4_LEN, &l4, 1);
			rta_add(&r.nh, IPXLAT_A_EAM_PREFIX6, &xl->eam6, 16);
			rta_add(&r.nh, IPXLAT_A_EAM_PREFIX6_LEN, &l6, 1);
			nest_end(&r.nh, n2);
			nest_end(&r.nh, n1);
		}
		nest_end(&r.nh, encap);
	}

	return nl_talk(&r);
}

/* NDP proxy entry (permanent: survives carrier loss) */
int nl_neigh_proxy(bool add, const struct in6_addr *addr, int ifindex)
{
	struct nlreq r = { 0 };

	r.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	r.nh.nlmsg_type = add ? RTM_NEWNEIGH : RTM_DELNEIGH;
	r.nh.nlmsg_flags = add ? NLM_F_CREATE | NLM_F_REPLACE : 0;
	r.nd.ndm_family = AF_INET6;
	r.nd.ndm_ifindex = ifindex;
	r.nd.ndm_flags = NTF_PROXY;
	r.nd.ndm_state = NUD_PERMANENT;
	rta_add(&r.nh, NDA_DST, addr, 16);
	return nl_talk(&r);
}
