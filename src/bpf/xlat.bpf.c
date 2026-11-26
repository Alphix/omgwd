// SPDX-License-Identifier: GPL-2.0-only
/* Copyright 2021 Toke Høiland-Jørgensen <toke@toke.dk> */
/* Copyright 2025 Mary Strodl <mstrodl@csh.rit.edu> */
/* Copyright 2026 Beniamino Galvani <bgalvani@redhat.com> */
/* Copyright 2026 David Härdeman <david@hardeman.nu> */
// Taken from NetworkManager/src/core/bpf/clat.bpf.c

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "xlat_cfg.h"

char _license[] SEC("license") = "GPL";

/*
 * Own ICMP header: <linux/icmp.h> pulls in libc headers via <linux/if.h>
 * with UAPI headers, and OpenWrt's CompileBPF uses the kernel's own.
 */
#define XLAT_ICMP_ECHOREPLY 0
#define XLAT_ICMP_ECHO 8
struct xlat_icmphdr {
	__u8 type;
	__u8 code;
	__u16 checksum;
	__u32 rest;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xlat_cfg);
} cfg SEC(".maps");

#define ETH_LEN sizeof(struct ethhdr)
#define IP_LEN sizeof(struct iphdr)
#define IP6_LEN sizeof(struct ipv6hdr)

struct icmpv6_pseudo {
	struct in6_addr saddr;
	struct in6_addr daddr;
	__u32 len;
	__u8 pad[3];
	__u8 nh;
} __attribute__((packed));

static __always_inline bool in96(const struct in6_addr *a, const __u32 *p)
{
	return a->s6_addr32[0] == p[0] && a->s6_addr32[1] == p[1] &&
	       a->s6_addr32[2] == p[2];
}

static __always_inline bool v6_to_v4(const struct xlat_cfg *c,
				     const struct in6_addr *a, __be32 *out)
{
	bool ok = c->has_p64 && in96(a, c->p64);

#pragma unroll
	for (int k = 0; k < XLAT_MAX_SI; k++)
		if (k < c->n_si && in96(a, c->si[k]))
			ok = true;
	if (ok)
		*out = a->s6_addr32[3];
	return ok;
}

static __always_inline void embed(const __u32 *p, __be32 a,
				  struct in6_addr *out)
{
	out->s6_addr32[0] = p[0];
	out->s6_addr32[1] = p[1];
	out->s6_addr32[2] = p[2];
	out->s6_addr32[3] = a;
}

static __always_inline __u16 xlat_csum_fold(__u32 csum)
{
	__u32 sum = (csum >> 16) + (csum & 0xffff);

	sum += sum >> 16;
	return ~sum;
}

static __always_inline void set_eth(struct __sk_buff *skb,
				    const struct xlat_cfg *c, __u16 proto)
{
	struct ethhdr eth;

	__builtin_memcpy(eth.h_dest, c->mac, ETH_ALEN);
	__builtin_memcpy(eth.h_source, c->mac, ETH_ALEN);
	eth.h_proto = bpf_htons(proto);
	bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0);
}

/* TCP/UDP: replace the pseudo-header addresses */
static __always_inline int fix_l4(struct __sk_buff *skb, __u8 proto,
				  __u32 l4off, void *from, int from_len,
				  void *to, int to_len)
{
	int flags = BPF_F_PSEUDO_HDR;
	__u32 off;
	__s64 csum = bpf_csum_diff(from, from_len, to, to_len, 0);

	if (proto == IPPROTO_TCP) {
		off = l4off + offsetof(struct tcphdr, check);
	} else {
		off = l4off + offsetof(struct udphdr, check);
		flags |= BPF_F_MARK_MANGLED_0;
	}
	return bpf_l4_csum_replace(skb, off, 0, csum, flags);
}

static __always_inline int handle_v6(struct __sk_buff *skb,
				     const struct xlat_cfg *c, bool forwarded)
{
	void *data = (void *)(long)skb->data,
	     *end = (void *)(long)skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_LEN;
	struct icmpv6_pseudo ph = { .nh = IPPROTO_ICMPV6 };
	struct iphdr ip4 = { .version = 4, .ihl = 5 };
	__be32 s4, d4;
	__u8 proto;

	if ((void *)(ip6 + 1) > end)
		return TC_ACT_OK;
	if (!v6_to_v4(c, &ip6->saddr, &s4) || !v6_to_v4(c, &ip6->daddr, &d4))
		return TC_ACT_SHOT; /* only translated traffic is routed here */

	proto = ip6->nexthdr;
	ip4.tos = ip6->priority << 4 | (ip6->flow_lbl[0] >> 4);
	ip4.frag_off = bpf_htons(1 << 14);
	ip4.ttl = ip6->hop_limit + (forwarded && ip6->hop_limit < 255);
	ip4.protocol = proto == IPPROTO_ICMPV6 ? IPPROTO_ICMP : proto;
	ip4.saddr = s4;
	ip4.daddr = d4;
	ip4.tot_len = bpf_htons(bpf_ntohs(ip6->payload_len) + IP_LEN);
	ip4.check =
		xlat_csum_fold(bpf_csum_diff(0, 0, (__be32 *)&ip4, IP_LEN, 0));

	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		if (fix_l4(skb, proto, ETH_LEN + IP6_LEN, &ip6->saddr, 32,
			   &ip4.saddr, 8))
			return TC_ACT_SHOT;
	} else if (proto == IPPROTO_ICMPV6) {
		struct icmp6hdr *ic6 = (void *)(ip6 + 1);
		__u16 old_tc, new_tc;
		__s64 csum;

		if ((void *)(ic6 + 1) > end)
			return TC_ACT_SHOT;
		if (ic6->icmp6_type == ICMPV6_ECHO_REQUEST)
			new_tc = XLAT_ICMP_ECHO;
		else if (ic6->icmp6_type == ICMPV6_ECHO_REPLY)
			new_tc = XLAT_ICMP_ECHOREPLY;
		else
			return TC_ACT_SHOT;
		old_tc = *(__u16 *)ic6;
		new_tc = bpf_htons(new_tc << 8);
		__builtin_memcpy(&ph.saddr, &ip6->saddr, 16);
		__builtin_memcpy(&ph.daddr, &ip6->daddr, 16);
		ph.len = bpf_htonl(bpf_ntohs(ip6->payload_len));
		csum = bpf_csum_diff((__be32 *)&ph, sizeof(ph), 0, 0, 0);
		if (bpf_l4_csum_replace(skb, ETH_LEN + IP6_LEN + 2, 0, csum,
					BPF_F_PSEUDO_HDR) ||
		    bpf_l4_csum_replace(skb, ETH_LEN + IP6_LEN + 2, old_tc,
					new_tc, 2) ||
		    bpf_skb_store_bytes(skb, ETH_LEN + IP6_LEN, &new_tc, 2, 0))
			return TC_ACT_SHOT;
	} else {
		return TC_ACT_SHOT;
	}

	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0) ||
	    bpf_skb_store_bytes(skb, ETH_LEN, &ip4, IP_LEN, 0))
		return TC_ACT_SHOT;
	set_eth(skb, c, ETH_P_IP);
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

static __always_inline int handle_v4(struct __sk_buff *skb,
				     const struct xlat_cfg *c, bool forwarded)
{
	void *data = (void *)(long)skb->data,
	     *end = (void *)(long)skb->data_end;
	struct iphdr *ip4 = data + ETH_LEN;
	struct ipv6hdr ip6 = { .version = 6 };
	struct icmpv6_pseudo ph = { .nh = IPPROTO_ICMPV6 };
	const __u32 *src_p = 0, *dst_p = 0;
	__u8 proto;

	if ((void *)(ip4 + 1) > end)
		return TC_ACT_OK;
	if (ip4->ihl != 5 || (ip4->frag_off & ~bpf_htons(1 << 14)))
		return TC_ACT_SHOT;

	if (c->has_p64 && ip4->daddr == c->pool_hp && c->hp_si < XLAT_MAX_SI) {
		src_p = c->p64;
		dst_p = c->si[c->hp_si & (XLAT_MAX_SI - 1)];
	} else {
#pragma unroll
		for (int k = 0; k < XLAT_MAX_SI; k++)
			if (k < c->n_si && ip4->daddr == c->pool[k])
				src_p = dst_p = c->si[k];
	}
	if (!src_p)
		return TC_ACT_SHOT;

	embed(src_p, ip4->saddr, &ip6.saddr);
	embed(dst_p, ip4->daddr, &ip6.daddr);
	proto = ip4->protocol;
	ip6.priority = (ip4->tos & 0xf0) >> 4;
	ip6.flow_lbl[0] = ip4->tos << 4;
	ip6.hop_limit = ip4->ttl + (forwarded && ip4->ttl < 255);
	ip6.nexthdr = proto == IPPROTO_ICMP ? IPPROTO_ICMPV6 : proto;
	ip6.payload_len = bpf_htons(bpf_ntohs(ip4->tot_len) - IP_LEN);

	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		if (fix_l4(skb, proto, ETH_LEN + IP_LEN, &ip4->saddr, 8,
			   &ip6.saddr, 32))
			return TC_ACT_SHOT;
	} else if (proto == IPPROTO_ICMP) {
		struct xlat_icmphdr *ic = (void *)(ip4 + 1);
		__u16 old_tc, new_tc;
		__s64 csum;

		if ((void *)(ic + 1) > end)
			return TC_ACT_SHOT;
		if (ic->type == XLAT_ICMP_ECHO)
			new_tc = ICMPV6_ECHO_REQUEST;
		else if (ic->type == XLAT_ICMP_ECHOREPLY)
			new_tc = ICMPV6_ECHO_REPLY;
		else
			return TC_ACT_SHOT;
		old_tc = *(__u16 *)ic;
		new_tc = bpf_htons(new_tc << 8);
		__builtin_memcpy(&ph.saddr, &ip6.saddr, 16);
		__builtin_memcpy(&ph.daddr, &ip6.daddr, 16);
		ph.len = bpf_htonl(bpf_ntohs(ip6.payload_len));
		csum = bpf_csum_diff(0, 0, (__be32 *)&ph, sizeof(ph), 0);
		if (bpf_l4_csum_replace(skb, ETH_LEN + IP_LEN + 2, 0, csum,
					BPF_F_PSEUDO_HDR) ||
		    bpf_l4_csum_replace(skb, ETH_LEN + IP_LEN + 2, old_tc,
					new_tc, 2) ||
		    bpf_skb_store_bytes(skb, ETH_LEN + IP_LEN, &new_tc, 2, 0))
			return TC_ACT_SHOT;
	} else {
		return TC_ACT_SHOT;
	}

	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0) ||
	    bpf_skb_store_bytes(skb, ETH_LEN, &ip6, IP6_LEN, 0))
		return TC_ACT_SHOT;
	set_eth(skb, c, ETH_P_IPV6);
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

SEC("tc")
int omgwd_xlat(struct __sk_buff *skb)
{
	__u32 key = 0;
	const struct xlat_cfg *c = bpf_map_lookup_elem(&cfg, &key);
	bool forwarded = skb->ingress_ifindex != 0;

	if (!c)
		return TC_ACT_SHOT;
	if (skb->protocol == bpf_htons(ETH_P_IPV6))
		return handle_v6(skb, c, forwarded);
	if (skb->protocol == bpf_htons(ETH_P_IP))
		return handle_v4(skb, c, forwarded);
	return TC_ACT_SHOT;
}
