// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"

/* Parse a presentation format name ("www.example.com", "\\046", "."). */
int dname_from_str(uint8_t *out, const char *str)
{
	size_t pos = 0, lpos = 0;
	const char *p = str;

	if (!str)
		return -1;

	if (!strcmp(str, ".")) {
		out[0] = 0;
		return 1;
	}

	out[0] = 0;
	pos = 1;

	while (*p) {
		int c = (unsigned char)*p++;

		if (c == '.') {
			if (out[lpos] == 0)
				return -1; /* empty label */
			lpos = pos++;
			if (pos > DNAME_MAX)
				return -1;
			out[lpos] = 0;
			continue;
		}

		if (c == '\\') {
			if (isdigit((unsigned char)p[0]) &&
			    isdigit((unsigned char)p[1]) &&
			    isdigit((unsigned char)p[2])) {
				c = (p[0] - '0') * 100 + (p[1] - '0') * 10 +
				    (p[2] - '0');
				if (c > 255)
					return -1;
				p += 3;
			} else if (*p) {
				c = (unsigned char)*p++;
			} else {
				return -1;
			}
		}

		if (out[lpos] >= LABEL_MAX || pos >= DNAME_MAX)
			return -1;

		out[pos++] = c;
		out[lpos]++;
	}

	if (out[lpos] != 0) {
		/* no trailing dot: terminate with the root label */
		if (pos >= DNAME_MAX)
			return -1;
		out[pos++] = 0;
	} else if (lpos != pos - 1) {
		return -1;
	}

	return pos;
}

int dname_to_str(const uint8_t *name, char *buf, size_t len)
{
	size_t o = 0;

	if (!len)
		return -1;

	if (!*name) {
		if (len < 2)
			return -1;
		strcpy(buf, ".");
		return 1;
	}

	while (*name) {
		unsigned int l = *name++;

		for (unsigned int i = 0; i < l; i++) {
			unsigned char c = name[i];

			if (c == '.' || c == '\\') {
				if (o + 2 >= len)
					return -1;
				buf[o++] = '\\';
				buf[o++] = c;
			} else if (c <= 0x20 || c >= 0x7f) {
				if (o + 4 >= len)
					return -1;
				o += snprintf(buf + o, len - o, "\\%03u", c);
			} else {
				if (o + 1 >= len)
					return -1;
				buf[o++] = c;
			}
		}
		name += l;

		if (*name) {
			if (o + 1 >= len)
				return -1;
			buf[o++] = '.';
		}
	}

	buf[o] = 0;
	return o;
}

size_t dname_len(const uint8_t *name)
{
	const uint8_t *p = name;

	while (*p)
		p += *p + 1;

	return p - name + 1;
}

void dname_lower(uint8_t *name)
{
	while (*name) {
		unsigned int l = *name++;

		for (unsigned int i = 0; i < l; i++)
			name[i] = tolower(name[i]);
		name += l;
	}
}

void dname_copy(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, dname_len(src));
}

bool dname_equal(const uint8_t *a, const uint8_t *b)
{
	size_t la = dname_len(a);

	if (la != dname_len(b))
		return false;

	for (size_t i = 0; i < la; i++)
		if (tolower(a[i]) != tolower(b[i]))
			return false;

	return true;
}

/* avl comparator for lowercase names */
int dname_cmp(const void *a, const void *b, void *ptr)
{
	size_t la = dname_len(a), lb = dname_len(b);
	int r = memcmp(a, b, la < lb ? la : lb);

	if (r)
		return r;

	return (int)la - (int)lb;
}

int dname_labels(const uint8_t *name)
{
	int n = 0;

	while (*name) {
		n++;
		name += *name + 1;
	}

	return n;
}

const uint8_t *dname_parent(const uint8_t *name)
{
	if (!*name)
		return NULL;

	return name + *name + 1;
}

bool dname_is_root(const uint8_t *name)
{
	return !*name;
}

/* true if name equals zone or is below it */
bool dname_is_subdomain(const uint8_t *name, const uint8_t *zone)
{
	int ln = dname_labels(name), lz = dname_labels(zone);

	if (ln < lz)
		return false;

	/* ln > lz guarantees a label to skip */
	while (ln-- > lz)
		name += *name + 1;

	return dname_equal(name, zone);
}

/* 64-bit FNV-1a over the lowercase wire name */
uint64_t dname_hash(const uint8_t *name)
{
	uint64_t h = 0xcbf29ce484222325ULL;
	size_t len = dname_len(name);

	for (size_t i = 0; i < len; i++) {
		h ^= (uint8_t)tolower(name[i]);
		h *= 0x100000001b3ULL;
	}

	/* final mix to spread FNV's weak low bits */
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;

	return h;
}

int dname_prepend(uint8_t *out, const char *label, const uint8_t *zone)
{
	size_t l = strlen(label), lz = dname_len(zone);

	if (!l || l > LABEL_MAX || l + 1 + lz > DNAME_MAX)
		return -1;

	out[0] = l;
	memcpy(out + 1, label, l);
	memcpy(out + 1 + l, zone, lz);

	return 1 + l + lz;
}

/* prefix is a (possibly multi-label) name; its root label is dropped */
int dname_concat(uint8_t *out, const uint8_t *prefix, const uint8_t *suffix)
{
	size_t lp = dname_len(prefix) - 1, ls = dname_len(suffix);

	if (lp + ls > DNAME_MAX)
		return -1;

	memmove(out, prefix, lp);
	memcpy(out + lp, suffix, ls);

	return lp + ls;
}

/* RFC 952/1123 hostname label(s): letters, digits, hyphen, dots between labels */
bool dname_valid_hostname(const char *str)
{
	size_t llen = 0, total = 0;

	if (!str || !*str)
		return false;

	for (const char *p = str; *p; p++, total++) {
		if (*p == '.') {
			if (!llen || p[-1] == '-')
				return false;
			llen = 0;
			continue;
		}

		if (!isalnum((unsigned char)*p) && !(*p == '-' && llen))
			return false;

		if (++llen > LABEL_MAX)
			return false;
	}

	return llen && total < 254 && str[total - 1] != '-';
}

static const uint8_t in_addr_arpa[] = "\7in-addr\4arpa";
static const uint8_t ip6_arpa[] = "\3ip6\4arpa";

int dname_from_addr(uint8_t *out, int family, const void *addr)
{
	char buf[128];
	size_t o = 0;

	if (family == AF_INET) {
		const uint8_t *a = addr;

		snprintf(buf, sizeof(buf), "%u.%u.%u.%u.in-addr.arpa", a[3],
			 a[2], a[1], a[0]);
		return dname_from_str(out, buf);
	}

	if (family == AF_INET6) {
		const uint8_t *a = addr;

		for (int i = 15; i >= 0; i--)
			o += snprintf(buf + o, sizeof(buf) - o, "%x.%x.",
				      a[i] & 0xf, a[i] >> 4);
		snprintf(buf + o, sizeof(buf) - o, "ip6.arpa");
		return dname_from_str(out, buf);
	}

	return -1;
}

static int hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';

	c = tolower(c);
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	return -1;
}

/* Parse a complete reverse name back into an address. */
bool dname_to_addr(const uint8_t *name, int *family, void *addr)
{
	int labels = dname_labels(name);
	const uint8_t *p = name;

	if (labels == 6 && dname_is_subdomain(name, in_addr_arpa)) {
		uint8_t *a = addr;

		for (int i = 3; i >= 0; i--) {
			unsigned int v = 0, l = *p++;

			if (!l || l > 3)
				return false;

			for (unsigned int j = 0; j < l; j++) {
				if (!isdigit(p[j]))
					return false;
				v = v * 10 + (p[j] - '0');
			}

			if (v > 255)
				return false;

			a[i] = v;
			p += l;
		}

		*family = AF_INET;
		return true;
	}

	if (labels == 34 && dname_is_subdomain(name, ip6_arpa)) {
		uint8_t *a = addr;

		memset(a, 0, 16);
		for (int i = 31; i >= 0; i--) {
			int v;

			if (*p != 1 || (v = hexval(p[1])) < 0)
				return false;

			a[i / 2] |= (i & 1) ? v : v << 4;
			p += 2;
		}

		*family = AF_INET6;
		return true;
	}

	return false;
}

/*
 * Reverse zone for a prefix. Only octet (IPv4) or nibble (IPv6) boundaries
 * are representable; the prefix is rounded down to the next boundary.
 */
int dname_reverse_zone(uint8_t *out, int family, const void *addr,
		       int prefix_len)
{
	char buf[128];
	size_t o = 0;

	if (family == AF_INET) {
		const uint8_t *a = addr;
		int octets = prefix_len / 8;

		for (int i = octets - 1; i >= 0; i--)
			o += snprintf(buf + o, sizeof(buf) - o, "%u.", a[i]);
		snprintf(buf + o, sizeof(buf) - o, "in-addr.arpa");
		return dname_from_str(out, buf);
	}

	if (family == AF_INET6) {
		const uint8_t *a = addr;
		int nibbles = prefix_len / 4;

		for (int i = nibbles - 1; i >= 0; i--) {
			int v = (i & 1) ? a[i / 2] & 0xf : a[i / 2] >> 4;

			o += snprintf(buf + o, sizeof(buf) - o, "%x.", v);
		}
		snprintf(buf + o, sizeof(buf) - o, "ip6.arpa");
		return dname_from_str(out, buf);
	}

	return -1;
}
