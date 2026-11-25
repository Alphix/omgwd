// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 David Härdeman <david@hardeman.nu>

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "omgwd.h"

int debug_level;
const char *uci_confdir;
const char *ubus_socket;

/* coarse is plenty: loop windows of seconds, record TTLs in seconds */
int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void reload_cb(struct uloop_signal *s)
{
	log_info("SIGHUP: reloading configuration");
	if (!config_load()) {
		iface_refresh();
		standin_changed();
	}
}

static struct uloop_signal reload_signal = {
	.signo = SIGHUP,
	.cb = reload_cb,
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		"  -C <dir>   UCI configuration directory (default /etc/config)\n"
		"  -Q <dir>   quirk table directory (default /usr/share/omgwd/quirks.d)\n"
		"  -u <path>  ubus socket\n"
		"  -d         debug logging\n"
		"  -s         log to stderr instead of syslog\n"
		"  -v         print the version\n",
		prog);
}

int main(int argc, char **argv)
{
	int log_dest = ULOG_SYSLOG;
	int ch;

	while ((ch = getopt(argc, argv, "C:Q:u:dsvh")) != -1) {
		switch (ch) {
		case 'C':
			uci_confdir = optarg;
			break;
		case 'Q':
			quirk_dir = optarg;
			break;
		case 'u':
			ubus_socket = optarg;
			break;
		case 'd':
			debug_level++;
			break;
		case 's':
			log_dest = ULOG_STDIO;
			break;
		case 'v':
			printf("omgwd %s\n", OMGWD_VERSION);
			return 0;
		default:
			usage(argv[0]);
			return ch == 'h' ? 0 : 1;
		}
	}

	ulog_open(log_dest, LOG_DAEMON, "omgwd");
	ulog_threshold(debug_level ? LOG_DEBUG : LOG_INFO);

	uloop_init();
	signal(SIGPIPE, SIG_IGN); /* nft exiting early must not kill us */

	if (config_load())
		return 1;

	iface_init();
	state_init();
	standin_init();
	if (mdns_init())
		return 1;
	ubus_init();
	uloop_signal_add(&reload_signal);

	log_info("omgwd %s started", OMGWD_VERSION);
	uloop_run();
	standin_shutdown(); /* routes, nftables tables and xlat0 go with us */
	uloop_done();
	return 0;
}
