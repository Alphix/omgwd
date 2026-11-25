// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <errno.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "omgwd.h"
#include "bpf/xlat_cfg.h"
#include "xlat_prog.h" /* generated: omgwd_xlat_insns, omgwd_xlat_map_relocs */

static int map_fd = -1, prog_fd = -1, link_fd = -1;
static int attached_ifindex;

static long sys_bpf(int cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int load_prog(void)
{
	size_t n = ARRAY_SIZE(omgwd_xlat_insns);
	struct bpf_insn *insns = malloc(n * sizeof(*insns));
	static char log[65536];
	union bpf_attr attr;
	int fd;

	if (!insns)
		return -ENOMEM;
	memcpy(insns, omgwd_xlat_insns, n * sizeof(*insns));
	for (size_t i = 0; i < ARRAY_SIZE(omgwd_xlat_map_relocs); i++) {
		struct bpf_insn *ld = &insns[omgwd_xlat_map_relocs[i]];

		ld->src_reg = BPF_PSEUDO_MAP_FD;
		ld->imm = map_fd;
		ld[1].imm = 0;
	}

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
	attr.expected_attach_type = BPF_TCX_EGRESS;
	attr.insns = (uintptr_t)insns;
	attr.insn_cnt = n;
	attr.license = (uintptr_t)"GPL";
	strncpy(attr.prog_name, "omgwd_xlat", sizeof(attr.prog_name) - 1);
	fd = sys_bpf(BPF_PROG_LOAD, &attr);
	if (fd < 0 && errno == EACCES) {
		/* verifier: load again with its log for the message */
		attr.log_level = 1;
		attr.log_buf = (uintptr_t)log;
		attr.log_size = sizeof(log);
		fd = sys_bpf(BPF_PROG_LOAD, &attr);
		if (fd < 0)
			log_err("BPF verifier:\n%s", log);
	}
	free(insns);
	return fd < 0 ? -errno : fd;
}

void bpf_xlat_unload(void)
{
	if (link_fd >= 0)
		close(link_fd);
	if (prog_fd >= 0)
		close(prog_fd);
	if (map_fd >= 0)
		close(map_fd);
	link_fd = prog_fd = map_fd = -1;
	attached_ifindex = 0;
}

/* load (if needed) and attach to tcx egress of ifindex; 0 or -errno */
int bpf_xlat_attach(int ifindex)
{
	union bpf_attr attr;
	int ret;

	if (link_fd >= 0 && attached_ifindex == ifindex)
		return 0;
	bpf_xlat_unload();

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(__u32);
	attr.value_size = sizeof(struct xlat_cfg);
	attr.max_entries = 1;
	strncpy(attr.map_name, "omgwd_cfg", sizeof(attr.map_name) - 1);
	map_fd = sys_bpf(BPF_MAP_CREATE, &attr);
	if (map_fd < 0) {
		ret = -errno;
		goto err;
	}

	prog_fd = load_prog();
	if (prog_fd < 0) {
		ret = prog_fd;
		prog_fd = -1;
		goto err;
	}

	memset(&attr, 0, sizeof(attr));
	attr.link_create.prog_fd = prog_fd;
	attr.link_create.target_ifindex = ifindex;
	attr.link_create.attach_type = BPF_TCX_EGRESS;
	link_fd = sys_bpf(BPF_LINK_CREATE, &attr);
	if (link_fd < 0) {
		ret = -errno;
		goto err;
	}
	attached_ifindex = ifindex;
	return 0;
err:
	log_warn("BPF translation backend: %s", strerror(-ret));
	bpf_xlat_unload();
	return ret;
}

int bpf_xlat_config(const struct xlat_cfg *cfg)
{
	union bpf_attr attr;
	__u32 key = 0;

	if (map_fd < 0)
		return -EBADF;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key = (uintptr_t)&key;
	attr.value = (uintptr_t)cfg;
	attr.flags = BPF_ANY;
	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr) < 0 ? -errno : 0;
}
