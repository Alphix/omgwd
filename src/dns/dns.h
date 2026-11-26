/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu> */

#ifndef ODNSD_DNS_H
#define ODNSD_DNS_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/* ---- protocol constants ------------------------------------------------ */

#define DNS_PORT 53
#define DOT_PORT 853
#define DNS_HDR_LEN 12
#define DNS_MAX_UDP 512
#define DNS_MAX_MSG 65535
#define DNAME_MAX 255
#define DNAME_STR_MAX 1025 /* worst case with \DDD escapes */
#define LABEL_MAX 63

/* header flags (host order, as in the 16-bit flags word) */
#define DNS_F_QR 0x8000
#define DNS_F_OPCODE_MASK 0x7800
#define DNS_F_OPCODE_SHIFT 11
#define DNS_F_AA 0x0400
#define DNS_F_TC 0x0200
#define DNS_F_RD 0x0100
#define DNS_F_RA 0x0080
#define DNS_F_AD 0x0020
#define DNS_F_CD 0x0010
#define DNS_F_RCODE_MASK 0x000f

enum dns_opcode {
	DNS_OP_QUERY = 0,
};

enum dns_rcode {
	DNS_RC_NOERROR = 0,
	DNS_RC_FORMERR = 1,
	DNS_RC_SERVFAIL = 2,
	DNS_RC_NXDOMAIN = 3,
	DNS_RC_NOTIMP = 4,
	DNS_RC_REFUSED = 5,
	DNS_RC_BADVERS = 16, /* extended, needs EDNS */
};

enum dns_class {
	DNS_C_IN = 1,
	DNS_C_CH = 3,
	DNS_C_ANY = 255,
};

enum dns_type {
	DNS_T_A = 1,
	DNS_T_NS = 2,
	DNS_T_MD = 3,
	DNS_T_MF = 4,
	DNS_T_CNAME = 5,
	DNS_T_SOA = 6,
	DNS_T_MB = 7,
	DNS_T_MG = 8,
	DNS_T_MR = 9,
	DNS_T_PTR = 12,
	DNS_T_HINFO = 13,
	DNS_T_MINFO = 14,
	DNS_T_MX = 15,
	DNS_T_TXT = 16,
	DNS_T_RP = 17,
	DNS_T_AFSDB = 18,
	DNS_T_RT = 21,
	DNS_T_PX = 26,
	DNS_T_AAAA = 28,
	DNS_T_SRV = 33,
	DNS_T_KX = 36,
	DNS_T_NAPTR = 35,
	DNS_T_A6 = 38,
	DNS_T_DNAME = 39,
	DNS_T_OPT = 41,
	DNS_T_DS = 43,
	DNS_T_SSHFP = 44,
	DNS_T_RRSIG = 46,
	DNS_T_NSEC = 47,
	DNS_T_DNSKEY = 48,
	DNS_T_NSEC3 = 50,
	DNS_T_NSEC3PARAM = 51,
	DNS_T_TLSA = 52,
	DNS_T_SVCB = 64,
	DNS_T_HTTPS = 65,
	DNS_T_IXFR = 251,
	DNS_T_AXFR = 252,
	DNS_T_ANY = 255,
	DNS_T_CAA = 257,
};

/* EDNS(0) */
#define EDNS_DO 0x8000 /* in the OPT TTL's flag half */
#define EDNS_OPT_PADDING 12
#define EDNS_OPT_EDE 15
#define EDNS_OPT_MAC 65001 /* raw MAC (dnsmasq --add-mac) */
#define EDNS_OPT_DEVICEID \
	65073 /* MAC as text/base64 (dnsmasq --add-mac=text|base64) */
#define EDNS_DEFAULT_SIZE 1232

/* Extended DNS Errors (RFC 8914) */
enum dns_ede {
	DNS_EDE_NONE = -1,
	DNS_EDE_OTHER = 0,
	DNS_EDE_UNSUPPORTED_DNSKEY_ALG = 1,
	DNS_EDE_UNSUPPORTED_DS_DIGEST = 2,
	DNS_EDE_STALE_ANSWER = 3,
	DNS_EDE_FORGED_ANSWER = 4,
	DNS_EDE_DNSSEC_INDETERMINATE = 5,
	DNS_EDE_DNSSEC_BOGUS = 6,
	DNS_EDE_SIGNATURE_EXPIRED = 7,
	DNS_EDE_SIGNATURE_NOT_YET_VALID = 8,
	DNS_EDE_DNSKEY_MISSING = 9,
	DNS_EDE_RRSIGS_MISSING = 10,
	DNS_EDE_NSEC_MISSING = 12,
	DNS_EDE_BLOCKED = 15,
	DNS_EDE_CENSORED = 16,
	DNS_EDE_FILTERED = 17,
	DNS_EDE_PROHIBITED = 18,
	DNS_EDE_NOT_READY = 14,
	DNS_EDE_NO_REACHABLE_AUTHORITY = 22,
	DNS_EDE_NETWORK_ERROR = 23,
};

/* DNSSEC validation state of data (RFC 4035 4.3) */
enum val_state {
	VAL_UNCHECKED, /* not validated (CD queries, DNSSEC off) */
	VAL_SECURE,
	VAL_INSECURE,
	VAL_BOGUS,
	VAL_INDETERMINATE,
};

/* ---- domain names (dname.c) ----------------------------------------------
 *
 * Names are kept in uncompressed wire format: a sequence of length-prefixed
 * labels terminated by the root label (0). Comparisons are done on lowercase
 * copies; dname_lower() produces one.
 */

int dname_from_str(uint8_t *out, const char *str);
int dname_to_str(const uint8_t *name, char *buf, size_t len);
size_t dname_len(const uint8_t *name);
void dname_lower(uint8_t *name);
void dname_copy(uint8_t *dst, const uint8_t *src);
bool dname_equal(const uint8_t *a, const uint8_t *b);
int dname_cmp(const void *a, const void *b, void *ptr);
bool dname_is_subdomain(const uint8_t *name, const uint8_t *zone);
int dname_labels(const uint8_t *name);
const uint8_t *dname_parent(const uint8_t *name);
bool dname_is_root(const uint8_t *name);
uint64_t dname_hash(const uint8_t *name);
int dname_prepend(uint8_t *out, const char *label, const uint8_t *zone);
int dname_concat(uint8_t *out, const uint8_t *prefix, const uint8_t *suffix);
bool dname_valid_hostname(const char *str);

/* reverse names (in-addr.arpa / ip6.arpa) */
int dname_from_addr(uint8_t *out, int family, const void *addr);
int dname_to_addr(const uint8_t *name, int *family, void *addr);
int dname_reverse_zone(uint8_t *out, int family, const void *addr,
		       int prefix_len);

/* ---- resource records (rr.c) -------------------------------------------- */

struct dns_rr {
	uint8_t name[DNAME_MAX + 1];
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlen;
	uint8_t *rdata; /* uncompressed; owned by the rr */
};

struct rr_list {
	struct dns_rr *rr;
	size_t n;
	size_t alloc;
};

void rr_list_init(struct rr_list *l);
void rr_list_free(struct rr_list *l);
struct dns_rr *rr_list_add(struct rr_list *l, const uint8_t *name,
			   uint16_t type, uint16_t class, uint32_t ttl,
			   const void *rdata, uint16_t rdlen);
int rr_list_append(struct rr_list *dst, const struct rr_list *src);

const char *rr_type_name(uint16_t type, char *buf, size_t len);
int rr_type_from_name(const char *name);
bool rr_type_has_names(uint16_t type);

int rr_rdata_from_str(uint16_t type, const char *str, uint8_t *out,
		      size_t outlen);
int rr_rdata_to_str(uint16_t type, const uint8_t *rdata, uint16_t rdlen,
		    char *buf, size_t len);

/* address hints in SVCB/HTTPS records (for rebind checks) */
typedef bool (*rr_addr_cb)(int family, const void *addr, void *priv);
bool rr_svcb_for_each_hint(const uint8_t *rdata, uint16_t rdlen, rr_addr_cb cb,
			   void *priv);

/* ---- wire format (wire.c) ------------------------------------------------ */

struct edns_info {
	bool present;
	uint16_t udp_size;
	uint8_t ext_rcode;
	uint8_t version;
	bool do_bit;
	int ede; /* received EDE code or DNS_EDE_NONE */
	uint8_t mac[6]; /* dnsmasq MAC option, if received */
	bool has_mac;
};

/* a question; in mDNS the top bit of qclass is the unicast-response (QU) bit */
struct dns_question {
	uint8_t name[DNAME_MAX + 1];
	uint16_t type;
	uint16_t class;
};

#define DNS_MAX_QUESTIONS 64

struct dns_msg {
	uint16_t id;
	uint16_t flags;
	uint8_t qname[DNAME_MAX + 1]; /* first question */
	uint16_t qtype;
	uint16_t qclass;
	bool has_question;
	struct dns_question *qd; /* all questions (mDNS has several) */
	size_t n_qd;
	struct rr_list an;
	struct rr_list ns;
	struct rr_list ar; /* without OPT */
	struct edns_info edns;
};

static inline unsigned int dns_msg_rcode(const struct dns_msg *m)
{
	return (m->flags & DNS_F_RCODE_MASK) | (m->edns.ext_rcode << 4);
}

static inline unsigned int dns_msg_opcode(const struct dns_msg *m)
{
	return (m->flags & DNS_F_OPCODE_MASK) >> DNS_F_OPCODE_SHIFT;
}

void dns_msg_init(struct dns_msg *m);
void dns_msg_free(struct dns_msg *m);
int wire_parse(const uint8_t *buf, size_t len, struct dns_msg *m,
	       bool question_only);
int wire_peek_id(const uint8_t *buf, size_t len, uint16_t *id);

struct wire_buf {
	uint8_t *buf;
	size_t len;
	size_t size; /* allocated */
	size_t limit; /* max message size (UDP payload limit) */
	bool truncated;
	/* name compression: offsets of names already written */
	uint16_t comp[64];
	unsigned int n_comp;
	size_t opt_reserve; /* bytes reserved for the OPT record */
};

int wire_init(struct wire_buf *w, size_t limit);
void wire_free(struct wire_buf *w);
int wire_put_header(struct wire_buf *w, uint16_t id, uint16_t flags);
int wire_put_question(struct wire_buf *w, const uint8_t *qname, uint16_t qtype,
		      uint16_t qclass);
int wire_put_rr(struct wire_buf *w, int section, const struct dns_rr *rr,
		uint32_t ttl);
int wire_put_opt(struct wire_buf *w, uint16_t udp_size, uint8_t ext_rcode,
		 bool do_bit, int ede, const char *ede_text, const uint8_t *mac,
		 size_t mac_len, uint16_t mac_code, size_t pad_block);
void wire_set_rcode(struct wire_buf *w, unsigned int rcode);
void wire_set_flags(struct wire_buf *w, uint16_t set, uint16_t clear);

enum wire_section {
	WIRE_AN = 0,
	WIRE_NS = 1,
	WIRE_AR = 2,
};

#endif
