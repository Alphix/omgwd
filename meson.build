# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

project('omgwd', 'c',
	license: 'GPL-2.0-or-later',
	meson_version: '>= 1.4.0',
	default_options: [
		'c_std=gnu23',
		'warning_level=2',
		'werror=true',
		'buildtype=minsize',
	])

fs = import('fs')
cc = meson.get_compiler('c')

add_project_arguments(
	'-D_GNU_SOURCE',
	'-Wno-unused-parameter',
	'-Wmissing-declarations',
	'-Wformat',
	'-Werror=format-security',
	'-Werror=implicit-function-declaration',
	language: 'c')

if get_option('b_sanitize').contains('undefined')
	add_project_arguments('-fno-sanitize-recover=undefined', language: 'c')
endif

deps = []
foreach lib : ['ubox', 'ubus', 'uci']
	deps += cc.find_library(lib)
endforeach

sources = files(
	'src/main.c',
	'src/config.c',
	'src/iface.c',
	'src/mdns.c',
	'src/repeat.c',
	'src/state.c',
	'src/xlat.c',
	'src/answer.c',
	'src/override.c',
	'src/standin.c',
	'src/ndp.c',
	'src/nl.c',
	'src/ubus.c',
	'src/dns/wire.c',
	'src/dns/dname.c',
	'src/dns/rr.c',
)
c_args = []

# the BPF backend: compile the program, embed it (tools/bpf2c.py), load it
# with the bare-bones loader. Remove this block and src/bpf/ when ipxlat is
# everywhere.
if get_option('bpf')
	if get_option('bpf_object') != ''
		bpf_obj = files(get_option('bpf_object'))
	else
		bpf_cflags = get_option('bpf_cflags')
		# "-target bpf" doesn't search the multiarch include directory
		# (Debian, Ubuntu), where <asm/types.h> lives; add it for native
		# builds unless bpf_cflags was given. clang has no -print-multiarch,
		# so ask gcc as well.
		if bpf_cflags.length() == 0 and not meson.is_cross_build()
			foreach cmd : [cc.cmd_array(), ['gcc']]
				r = run_command(cmd + ['-print-multiarch'], check: false)
				multiarch = r.returncode() == 0 ? r.stdout().strip() : ''
				inc = '/usr/include' / multiarch
				if multiarch != '' and fs.exists(inc / 'asm/types.h')
					bpf_cflags += '-I' + inc
					break
				endif
			endforeach
		endif
		bpf_obj = custom_target('xlat.bpf.o',
			input: 'src/bpf/xlat.bpf.c',
			output: 'xlat.bpf.o',
			depend_files: files('src/bpf/xlat_cfg.h'),
			command: [find_program(get_option('bpf_cc')),
				'-std=gnu23', '-O2', '-g', '-Wall', '-target', 'bpf', bpf_cflags,
				'-I' + meson.current_source_dir() / 'src/bpf',
				'-c', '@INPUT@', '-o', '@OUTPUT@'])
	endif
	xlat_prog = custom_target('xlat_prog.h',
		input: bpf_obj,
		output: 'xlat_prog.h',
		depend_files: files('tools/bpf2c.py'),
		command: [find_program('python3'), files('tools/bpf2c.py'),
			'@INPUT@', 'tc', 'cfg', '@OUTPUT@', 'omgwd_xlat'])
	sources += [files('src/bpf/loader.c'), xlat_prog]
	c_args += '-DOMGWD_BPF'
endif

executable('omgwd', sources,
	c_args: c_args,
	include_directories: include_directories('src'),
	dependencies: deps,
	install: true,
	install_dir: get_option('sbindir'))
