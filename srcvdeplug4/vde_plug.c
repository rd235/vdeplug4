/* 
 * Copyright (C) 2002-2016  Renzo Davoli, University of Bologna
 * Modified by Ludovico Gardenghi 2005
 * 
 * vde_plug: connect vde network together
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <stdarg.h>
#include <poll.h>

#include <libvdeplug.h>
#include <vde_plug_log.h>
#include <vde_plug_iplog.h>
#include <openclosepidfile.h>
#include <selfsighandler.h>

#define VDE_IP_LOG_GROUP "vdeplug_iplog"
#define DEFAULT_DESCRIPTION "vdeplug:"

int vde_ip_log;

VDECONN *conn;
VDECONN *conn2;
VDESTREAM *vdestream;

#define ETH_ALEN 6
#define ETH_HDRLEN (ETH_ALEN+ETH_ALEN+2)

struct utsname me;
#define myname me.nodename

void vdeplug_err(void *opaque, int type, char *format,...)
{
	va_list args;

	if (isatty(STDERR_FILENO)) {
		fprintf(stderr, "%s: Packet length error ",myname);
		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);
		fprintf(stderr,"\n");
	}
}

ssize_t vdeplug_recv(void *opaque, void *buf, size_t count)
{
	VDECONN *conn=opaque;
	if (__builtin_expect(vde_ip_log != 0, 0))
		vde_ip_check(buf,count);
	return vde_send(conn,(char *)buf,count,0);
}


int checkuidgroup(uid_t uid, const char *group) {
	struct passwd *pw=getpwuid(uid);
	int ngroups=0;
	if (pw == NULL) return -1;
	if (getgrouplist(pw->pw_name, pw->pw_gid, NULL, &ngroups) < 0) {
		gid_t gids[ngroups];
		if (getgrouplist(pw->pw_name, pw->pw_gid, gids, &ngroups) == ngroups) {
			struct group *grp;
			int i;
			while ((grp=getgrent()) != NULL) {
				for (i=0; i<ngroups; i++) {
					if (grp->gr_gid == gids[i] && strcmp(grp->gr_name,group) == 0) {
						endgrent();
						return 1;
					}
				}
			}
			endgrent();
			return 0;
		}
	}
	return -1;
}

static void cleanup(void)
{
  vde_close(conn);
	if (conn2 != NULL) vde_close(conn2);
	if (vdestream != NULL) vdestream_close(vdestream);
	openclosepidfile(NULL);
}

unsigned char bufin[VDE_ETHBUFSIZE];

int plug2stream(void) {
	register ssize_t nx;
	struct pollfd pollv[] = {
		{STDIN_FILENO, POLLIN|POLLHUP},
		{vde_datafd(conn), POLLIN|POLLHUP},
		{vde_ctlfd(conn), POLLIN|POLLHUP},
	};

	vdestream = vdestream_open(conn,STDOUT_FILENO,vdeplug_recv,vdeplug_err);

	for(;;) {
		poll(pollv,3,-1);
		if (__builtin_expect(((pollv[0].revents | pollv[1].revents | pollv[2].revents) & POLLHUP ||
						pollv[2].revents & POLLIN),0))
			break;
		if (pollv[0].revents & POLLIN) {
			nx = read(STDIN_FILENO,bufin,sizeof(bufin));
			/* if POLLIN but not data it means that the stream has been
			 * closed at the other end */
			/*fprintf(stderr,"%s: RECV %d %x %x \n",myname,nx,bufin[0],bufin[1]);*/
			if (nx == 0)
				break;
			vdestream_recv(vdestream, bufin, nx);
		}
		if (pollv[1].revents & POLLIN) {
			nx = vde_recv(conn,bufin,VDE_ETHBUFSIZE,0);
			if (__builtin_expect((nx >= ETH_HDRLEN),1))
			{
				vdestream_send(vdestream, bufin, nx);
				/*fprintf(stderr,"%s: SENT %d %x %x \n",myname,nx,bufin[0],bufin[1]);*/
			} else if (nx<0)
				perror("vde_plug: recvfrom ");
		}
	}
	return(0);
}

int plug2cmd(char **argv) {
	int p2c[2],c2p[2];
	pid_t pid;
	if (pipe(p2c) < 0 || pipe(c2p) < 0) {
		perror("pipe open");
		return(1);
	}

	pid=fork();
	if (pid < 0) {
		perror("fork");
		exit(1);
	} else if (pid == 0) {
		dup2(p2c[0], STDIN_FILENO);
		dup2(c2p[1], STDOUT_FILENO);
		close(p2c[0]); close(p2c[1]);
		close(c2p[0]); close(c2p[1]);
		execvp(*argv, argv);
		exit(1);
	}
	dup2(c2p[0], STDIN_FILENO);
	dup2(p2c[1], STDOUT_FILENO);
	close(p2c[0]); close(p2c[1]);
	close(c2p[0]); close(c2p[1]);

	return plug2stream();
}

int plug2plug(void)
{
	register ssize_t nx;
	struct pollfd pollv[] = {
		{vde_datafd(conn), POLLIN|POLLHUP},
		{vde_datafd(conn2), POLLIN|POLLHUP},
		{vde_ctlfd(conn), POLLIN|POLLHUP},
		{vde_ctlfd(conn2), POLLIN|POLLHUP}
	};

	for(;;) {
		poll(pollv,4,-1);
		if ((pollv[0].revents | pollv[1].revents | pollv[2].revents | pollv[2].revents) & POLLHUP ||
				(pollv[2].revents | pollv[3].revents) & POLLIN)
			break;
		if (pollv[0].revents & POLLIN) {
			nx = vde_recv(conn, bufin, VDE_ETHBUFSIZE,0);
			if (__builtin_expect((nx >= ETH_HDRLEN),1)) {
				vde_send(conn2, bufin, nx, 0);
				/*fprintf(stderr,"0->1 %d ",nx);*/
			} else if (nx<0)
				break;
		}
		if (pollv[1].revents & POLLIN) {
			nx = vde_recv(conn2,bufin,VDE_ETHBUFSIZE,0);
			if (__builtin_expect((nx >= ETH_HDRLEN),1)) {
				vde_send(conn, bufin, nx, 0);
				/*fprintf(stderr,"1->0 %d ",nx);*/
			} else if (nx<0)
				break;
		}
	}
	return(0);
}


static void netusage_and_exit() {
	vdeplug_openlog("FAILED");
	fprintf (stderr,"This is a Virtual Distributed Ethernet (vde) tunnel broker. \n"
			"This is not a login shell, only vde_plug can be executed\n");
	exit(-1);
}

static void usage_and_exit(char *progname) {
	fprintf (stderr,"Usage:\n"
			"  %s [ OPTIONS ] \n"
			"  %s [ OPTIONS ] vde_plug_url\n"
			"  %s [ OPTIONS ] vde_plug_url vde_plug_url\n"
			"  %s [ OPTIONS ] = command [args ...]\n"
			"  %s [ OPTIONS ] vde_plug_url = command [args ...]\n"
			"  an omitted or empty '' vde_plug_url refer to the default vde service\n"
			"  i.e. what defined in \"~/.vde2/default.switch\" or\n"
			"       a standard switch defined by libvdeplug_vde.so (e.g. /var/run/vde.ctl)\n"
			"Options:\n"
			"  -d | --daemon:            daemonize the program\n"
			"  -p PIDFILE | --pidfile PIDFILE: \n"
			"                            write pid of daemon to PIDFILE\n"
			"  -l | --log:               log START/STOP of vde_plug on syslog\n"
			"  -L | --iplog:             -l plus log the IP addresses used\n"
			"  -h | --help:              show this short summary\n"
			"  -g GROUP | -group GROUP:  set the group ownership (for vde://...)\n"
			"  -G GROUP | -group2 GROUP: like -g, for the second plug\n"
			"  -m MODE | -mod MODE:      comm socket protection mode (see chmod) (for vde://...)\n"
			"  -M MODE | -mod2 MODE:     like -m, for the second plug\n"
			"  --port PORT1, --port2 PORT2:\n"
			"                            obsolete options, set the vde switch port,\n"
			"                            use [port] suffix in the vde_plug_url instead\n"
			"  -D DESCR | --descr DESCR  set the description of this connection to DESCR\n"
			"                            (the default value is \"" DEFAULT_DESCRIPTION "\"\n"
			"\n",progname,progname,progname,progname,progname);
	exit(-1);
}

char short_options[] = "c:hp:dm:M:g:G:lLD:";
struct option long_options[] = {
	{"pidfile",  required_argument, 0, 'p' },
	{"daemon",   no_argument,       0, 'd' },
	{"port",     required_argument, 0, 0x100 + 'p'},
	{"port2",    required_argument, 0, 0x100 + 'P'},
	{"mod",      required_argument, 0, 'm'},
	{"mod2",     required_argument, 0, 'M'},
	{"group",    required_argument, 0, 'g'},
	{"group2",   required_argument, 0, 'G'},
	{"descr",    required_argument, 0, 'D' },
	{"log",      no_argument,       0, 'l' },
	{"iplog",    no_argument,       0, 'L' },
	{"help",     no_argument,       0, 'h' },
	{0, 0, 0, 0}
};

#include <syslog.h>
int main(int argc, char *argv[])
{
	char *progname = basename(argv[0]);
	static char *vde_url = NULL;
	static char *vde_url2 = NULL;
	static char **cmdargv = NULL;
	struct vde_open_args open_args = {.port = 0,.group = NULL,.mode = 0700};
	struct vde_open_args open_args2 = {.port = 0,.group = NULL,.mode = 0700};
	int daemonize = 0;
	char *pidfile = NULL;
	char *description = DEFAULT_DESCRIPTION;

	uname(&me);

	if (argv[0][0] == '-')
		netusage_and_exit(); //implies exit
	/* option parsing */
	while (1) {
		int option_index = 0;
		int c;

		c = getopt_long(argc, argv, short_options, long_options, &option_index);
		if (c == -1) break;

		switch (c) {
			case 'c':
				if (strcmp(optarg,"vde_plug") == 0) {
					vdeplug_openlog(NULL);
					atexit(vdeplug_closelog);
					if (checkuidgroup(getuid(), VDE_IP_LOG_GROUP) == 1)
						vde_ip_log = 1;
				}
				else
					netusage_and_exit(); //implies exit
				break;

			case 0x100 + 'p':
				open_args.port = atoi(optarg);
				if (open_args.port <= 0)
					usage_and_exit(progname); //implies exit
				break;

			case 0x100 + 'P':
				open_args2.port = atoi(optarg);
				if (open_args2.port <= 0)
					usage_and_exit(progname); //implies exit
				break;

			case 'h':
				usage_and_exit(progname); //implies exit
				break;

			case 'm': 
				sscanf(optarg,"%o",(unsigned int *)&(open_args.mode));
				break;

			case 'M': 
				sscanf(optarg,"%o",(unsigned int *)&(open_args2.mode));
				break;

			case 'g':
				open_args.group = optarg;
				break;

			case 'G':
				open_args2.group = optarg;
				break;

			case 'L':
				vde_ip_log = 1;

			case 'l':
				vdeplug_openlog(NULL);
				atexit(vdeplug_closelog);
				break;

			case 'p' : 
				pidfile = optarg;
				break;

			case 'd' : 
				daemonize = 1;
				break;

			case 'D' : 
				if (*optarg != 0)
					description = optarg;
				break;

			default:
				usage_and_exit(progname); //implies exit
		}
	}

	argv += optind;
	argc -= optind;

	switch (argc) {
		case 0: break;
		case 1: vde_url = *argv;
						break;
		case 2: if (strcmp(argv[0],"=") == 0)
							cmdargv = argv+1;
						else {
							vde_url = argv[0];
							vde_url2 = argv[1];
						}
						break;
		default: if (strcmp(argv[0],"=") == 0)
							 cmdargv = argv+1;
						 else if (strcmp(argv[1],"=") == 0) {
							 vde_url = argv[0];
							 cmdargv = argv+2;
						 } else
							 usage_and_exit(progname); //implies exit
						 break;
	}

	if (daemonize != 0) {
		if (daemon(0,0) < 0) {
			fprintf(stderr,"%s daemonize: %s\n", progname, strerror(errno));
			exit(1);
		}
	}

	if (pidfile != NULL)
		openclosepidfile(pidfile);

	atexit(cleanup);
	setsighandlers(cleanup);

	conn = vde_open(vde_url, description, &open_args);
	if (conn == NULL) {
		fprintf(stderr,"vde_open %s: %s\n",vde_url && *vde_url ? vde_url : "default switch", strerror(errno));
		exit(1);
	}
	if (vde_url2 != NULL) {
		conn2 = vde_open(vde_url2, description, &open_args2);
		if (conn2 == NULL) {
			fprintf(stderr,"vde_open %s: %s\n",vde_url2 && *vde_url2 ? vde_url2 : "default switch", strerror(errno));
			exit(1);
		}
		return plug2plug();
	} else if (cmdargv != NULL)
		return plug2cmd(cmdargv);
	else
		return plug2stream();
}
