/* 
 * Copyright (C) 2003-2016  Renzo Davoli, Ludovico Gardenghi. University of Bologna
 * 
 * signal handler
 *
 * VDE is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>. 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <selfsighandler.h>

static void (*cleanupcopy)(void);

static void sig_handler(int sig)
{
	cleanupcopy();
	signal(sig, SIG_DFL);
	if (sig == SIGTERM)
		_exit(0);
	else
		kill(-getpgrp(), sig);
}

void setsighandlers(void (*cleanup)(void))
{
	/* setting signal handlers.
	 * sets clean termination for SIGHUP, SIGINT and SIGTERM, and simply
	 * ignores all the others signals which could cause termination. */
	struct { int sig; const char *name; int ignore; } signals[] = {
		{ SIGHUP, "SIGHUP", 0 },
		{ SIGINT, "SIGINT", 0 },
		{ SIGPIPE, "SIGPIPE", 1 },
		{ SIGALRM, "SIGALRM", 1 },
		{ SIGTERM, "SIGTERM", 0 },
		{ SIGUSR1, "SIGUSR1", 1 },
		{ SIGUSR2, "SIGUSR2", 1 },
		{ SIGPROF, "SIGPROF", 1 },
		{ SIGVTALRM, "SIGVTALRM", 1 },
#ifdef SIGPOLL
		{ SIGPOLL, "SIGPOLL", 1 },
#ifdef SIGSTKFLT
		{ SIGSTKFLT, "SIGSTKFLT", 1 },
#endif
		{ SIGIO, "SIGIO", 1 },
		{ SIGPWR, "SIGPWR", 1 },
#ifdef SIGUNUSED
		{ SIGUNUSED, "SIGUNUSED", 1 },
#endif
#endif
#ifdef VDE_DARWIN
		{ SIGXCPU, "SIGXCPU", 1 },
		{ SIGXFSZ, "SIGXFSZ", 1 },
#endif
		{ 0, NULL, 0 }
	};

	int i;
	struct sigaction sa = {
		.sa_handler = sig_handler,
		.sa_flags = 0};
	sigfillset(&sa.sa_mask);
	for(i = 0; signals[i].sig != 0; i++)
		if (!signals[i].ignore)
			if (sigaction(signals[i].sig, &sa, NULL) < 0)
				perror("Setting handler");
	for(i = 0; signals[i].sig != 0; i++)
		if (signals[i].ignore)
			if (signal(signals[i].sig, SIG_IGN) == SIG_ERR)
				perror("Setting handler");

	cleanupcopy = cleanup;
}
