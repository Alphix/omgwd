/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/* SPDX-FileCopyrightText: 2026 Mandelbit SRL */
/* SPDX-FileCopyrightText: 2026 Daniel Gröber <dxld@darkboxed.org> */
/* SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu> */
/* Fallback definitions from the ipxlat UAPI (include/uapi/linux/ipxlat.h) */

#ifndef OMGWD_IPXLAT_COMPAT_H
#define OMGWD_IPXLAT_COMPAT_H

#include <linux/lwtunnel.h>

#ifndef LWTUNNEL_ENCAP_IPXLAT
#define LWTUNNEL_ENCAP_IPXLAT 11
#endif

#ifndef IPXLAT_A_MAX
enum {
	IPXLAT_A_UNSPEC,
	IPXLAT_A_RFC6052_PREFIX6,
	IPXLAT_A_EAMT,
	IPXLAT_A_XMIT, /* flag: translate after POST_ROUTING (our RFC) */
};

enum {
	IPXLAT_A_PREFIX6_UNSPEC,
	IPXLAT_A_PREFIX6_ADDR,
	IPXLAT_A_PREFIX6_LEN,
};

enum {
	IPXLAT_A_EAM_UNSPEC,
	IPXLAT_A_EAM_PREFIX4,
	IPXLAT_A_EAM_PREFIX4_LEN,
	IPXLAT_A_EAM_PREFIX6,
	IPXLAT_A_EAM_PREFIX6_LEN,
};
#endif

#endif
