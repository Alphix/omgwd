/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu> */

#ifndef OMGWD_XLAT_CFG_H
#define OMGWD_XLAT_CFG_H

#include <linux/types.h>

#define XLAT_MAX_SI 8 /* client networks with stand-ins (power of two) */

struct xlat_cfg {
	__u32 n_si;
	__u32 si[XLAT_MAX_SI][3]; /* stand-in /96 of client network k */
	__be32 pool[XLAT_MAX_SI]; /* its SNAT pool address */
	__u32 has_p64;
	__u32 p64[3]; /* PREF64 /96 */
	__be32 pool_hp; /* hairpin pool address ... */
	__u32 hp_si; /* ... living in si[hp_si] */
	__u8 mac[6]; /* xlat0's MAC (frames re-enter addressed to it) */
	__u8 pad[2];
};

#endif
