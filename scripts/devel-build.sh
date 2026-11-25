#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

BINARY_NAME="omgwd"

set -euxo pipefail
cd "${0%/*}"
cd ..

# Sanity checks
if [ ! -e "meson.build" ] || [ ! -e "src/${BINARY_NAME}.h" ]; then
	echo "${BINARY_NAME} checkout not found" >&2
	exit 1
fi

if [ $# -eq 0 ]; then
	BUILD_ARGS=""
else
	BUILD_ARGS="$@"
fi

# Create build dirs
OMGWDDIR="$(pwd)"
BUILDDIR="${OMGWDDIR}/build"
DEPSDIR="${OMGWDDIR}/depends"
PREFIX="${DEPSDIR}/install"

# --clean: remove build/ and depends/, but keep the dependency checkouts if
# any has local changes, new files or commits (they are built out of tree)
if [ "${1:-}" = "--clean" ]; then
	keep=""
	for dep in "${DEPSDIR}"/*/.git; do
		[ -e "${dep}" ] || continue
		dep="${dep%/.git}"
		if [ -n "$(git -C "${dep}" status --porcelain)" ] ||
		   [ "$(git -C "${dep}" rev-list --count '@{upstream}..HEAD' 2>/dev/null || echo 1)" != "0" ]; then
			keep="${keep} ${dep}"
		fi
	done
	rm -rf "${BUILDDIR}" "${PREFIX}" "${DEPSDIR}/build"
	if [ -n "${keep}" ]; then
		set +x
		echo "Not removing ${DEPSDIR}, local changes in:${keep}" >&2
		exit 1
	fi
	rm -rf "${DEPSDIR}"
	exit 0
fi

[ -e "${DEPSDIR}" ] || mkdir "${DEPSDIR}"

# Download deps
cd "${DEPSDIR}"
[ -e "libubox" ] || git clone https://github.com/openwrt/libubox.git
[ -e "uci" ] || git clone https://github.com/openwrt/uci.git
[ -e "ubus" ] || git clone https://github.com/openwrt/ubus.git

# Build libubox
cmake							\
	-S "${DEPSDIR}/libubox"				\
	-B "${DEPSDIR}/build/libubox"			\
	-DCMAKE_PREFIX_PATH="${PREFIX}"		\
	-DBUILD_LUA=OFF					\
	-DBUILD_EXAMPLES=OFF				\
	--install-prefix "${PREFIX}"
cmake --build "${DEPSDIR}/build/libubox"
cmake --install "${DEPSDIR}/build/libubox"

# Build ubus
cmake							\
	-S "${DEPSDIR}/ubus"				\
	-B "${DEPSDIR}/build/ubus"			\
	-DCMAKE_PREFIX_PATH="${PREFIX}"		\
	-DBUILD_LUA=OFF					\
	-DBUILD_STATIC=OFF				\
	-DBUILD_EXAMPLES=OFF				\
	--install-prefix "${PREFIX}"
cmake --build "${DEPSDIR}/build/ubus"
cmake --install "${DEPSDIR}/build/ubus"

# Build uci
cmake							\
	-S "${DEPSDIR}/uci"				\
	-B "${DEPSDIR}/build/uci"			\
	-DCMAKE_PREFIX_PATH="${PREFIX}"		\
	-DBUILD_LUA=OFF					\
	-DBUILD_STATIC=OFF				\
	--install-prefix "${PREFIX}"
cmake --build "${DEPSDIR}/build/uci"
cmake --install "${DEPSDIR}/build/uci"

# Build project
cd "${OMGWDDIR}"
[ -e "${BUILDDIR}/build.ninja" ] && SETUP_ARGS="--reconfigure" || SETUP_ARGS=""
CFLAGS="-I${PREFIX}/include"					\
LDFLAGS="-L${PREFIX}/lib -Wl,-rpath,${PREFIX}/lib"		\
meson setup ${SETUP_ARGS} "${BUILDDIR}" ${BUILD_ARGS}
meson compile -C "${BUILDDIR}"

set +x
echo "✅ Success - the ${BINARY_NAME} binary is available at ${BUILDDIR}/${BINARY_NAME}"
echo "👷 You can rebuild ${BINARY_NAME} by running 'meson compile -C build'"

exit 0
