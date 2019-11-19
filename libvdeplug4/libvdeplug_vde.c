/*
 * libvdeplug - A library to connect to a VDE Switch.
 * Copyright (C) 2013-2017 Renzo Davoli, University of Bologna
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <libvdeplug.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "libvdeplug_mod.h"

static VDECONN *vde_vde_open(char *given_vde_url, char *descr, int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_vde_recv(VDECONN *conn, void *buf, size_t len, int flags);
static ssize_t vde_vde_send(VDECONN *conn, const void *buf, size_t len, int flags);
static int vde_vde_datafd(VDECONN *conn);
static int vde_vde_ctlfd(VDECONN *conn);
static int vde_vde_close(VDECONN *conn);

struct vdeplug_module vdeplug_ops={
	.vde_open_real=vde_vde_open,
	.vde_recv=vde_vde_recv,
	.vde_send=vde_vde_send,
	.vde_datafd=vde_vde_datafd,
	.vde_ctlfd=vde_vde_ctlfd,
	.vde_close=vde_vde_close};

struct vde_vde_conn {
	void *hadle;
	struct vdeplug_module *module;
	int fdctl;
	int fddata;
};

/* Fallback names for the control socket, NULL-terminated array of absolute
 * filenames. */
static const char *fallback_vde_url[] = {
	"/var/run/vde.ctl",
	"/tmp/vde.ctl",
	NULL,
};

/* Fallback directories for the data socket, NULL-terminated array of absolute
 * directory names, with no trailing /. */
static const char *fallback_dirname[] = {
	"/var/run",
	"/var/tmp",
	"/tmp",
	NULL,
};

#define SWITCH_MAGIC 0xfeedface
enum request_type { REQ_NEW_CONTROL, REQ_NEW_PORT0 };

struct request_v3 {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
	struct sockaddr_un sock;
	char description[MAXDESCR];
} __attribute__((packed));

/* return value: -1=error; 0=portgroup socket okay; 1=connected to generic "ctl" port */
static int try2connect(int fdctl, const char *url, char *portgroup, int port, struct sockaddr_un *ctlsock) {
	int res = -1;

	memset(ctlsock, 0, sizeof(*ctlsock));
	ctlsock->sun_family = AF_UNIX;
	if (portgroup) {
		snprintf(ctlsock->sun_path, sizeof(ctlsock->sun_path), "%s/%s", url, portgroup);
		res = connect(fdctl, (struct sockaddr *) ctlsock, sizeof(*ctlsock));
	}
	if (res < 0 || port != 0) {
		snprintf(ctlsock->sun_path, sizeof(ctlsock->sun_path), "%s/ctl", url);
		res = connect(fdctl, (struct sockaddr *) ctlsock, sizeof(*ctlsock));
		if (res == 0) res = 1;
	}
	return res;
}

static VDECONN *vde_vde_open(char *given_vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	struct request_v3 req;
	int port=0;
	char *portgroup=NULL;
	char str_lenofint = snprintf(NULL, 0, "%d ", INT_MIN); // # of char to store a int
	char numeric_portgroup[str_lenofint];
	char *group=NULL;
	char *modestr=NULL;
	mode_t mode=0700;
	char real_vde_url[PATH_MAX];
	int fdctl=-1;
	int fddata=-1;
	struct sockaddr_un sockun;
	struct sockaddr_un datasock;
	const char *vde_url=NULL;
	int res;
	int pid=getpid();
	int sockno=0;
	struct vde_vde_conn *newconn;
	struct vdeparms parms[] = {{"", &portgroup}, {"port", &portgroup}, {"portgroup", &portgroup},
		{"group", &group}, {"mode", &modestr}, {NULL, NULL}};

	if (open_args != NULL) {
		if (interface_version == 1) {
			port=open_args->port;
			group=open_args->group;
			mode=open_args->mode;
		} else {
			errno=EINVAL;
			goto abort;
		}
	}

	if (vde_parsepathparms(given_vde_url, parms) < 0) {
		errno=EINVAL;
		goto abort;
	}

	if (modestr) 
		mode = strtol(modestr, NULL, 8);

	/* Canonicalize the sockname: we need to send an absolute pathname to the
	 * switch (we don't know its cwd) for the data socket. Appending
	 * given_sockname to getcwd() would be enough, but we could end up with a
	 * name longer than PATH_MAX that couldn't be used as sun_path. */
	if (*given_vde_url && realpath(given_vde_url, real_vde_url) == NULL)
		goto abort;
	vde_url=real_vde_url;

	/* if port is given as a open_arg, convert it to portgroup */
	if ((portgroup == NULL || *portgroup == 0) && port != 0) {
		snprintf(numeric_portgroup, str_lenofint, "%d", port < 0 ? 0 : port);
		portgroup = numeric_portgroup;
	} else if (portgroup != NULL && isdigit(*portgroup)) {
	/* else if portgroup is a number, convert it to port (and override port) */
		char *endptr;
		int portgroup2port = strtol(portgroup, &endptr, 10);
		if (*endptr == 0) {
			port = portgroup2port;
			if (port == 0) port = -1;
		}
	}

	/* connection to a vde_switch */
	if((fdctl = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0)
		goto abort;
	if((fddata = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)) < 0)
		goto abort;

	/* If we're given a vde_url, just try it (remember: vde_url is the
	 * canonicalized version of given_vde_url - though we don't strictly need
	 * the canonicalized version here). vde_url should be the name of a
	 * *directory* which contains the control socket, named ctl. Older
	 * versions of VDE used a socket instead of a directory (so an additional
	 * attempt with %s instead of %s/ctl could be made), but they should
	 * really not be used anymore. */
	if (*given_vde_url)
		res = try2connect(fdctl, vde_url, portgroup, port, &sockun);
	/* Else try all the fallback vde_url, one by one */
	else
	{
		int i;
		for (i = 0, res = -1; fallback_vde_url[i] && (res < 0); i++)
		{
			vde_url = fallback_vde_url[i];
			res = try2connect(fdctl, vde_url, portgroup, port, &sockun);
		}
	}

	if (res < 0)
		goto abort;

	req.magic=SWITCH_MAGIC;
	req.version=3;
	req.type = REQ_NEW_CONTROL;
	/* bw compatibility, port embedded on type if connected to ctl */
	if (res > 0 && port != 0) {
		if (port < 0) 
			req.type = REQ_NEW_PORT0;
		else
			req.type=req.type+(port << 8);
	}
	strncpy(req.description, descr, MAXDESCR);

	datasock.sun_family = AF_UNIX;
	memset(datasock.sun_path, 0, sizeof(datasock.sun_path));
	do
	{
		/* Here vde_url is the last successful one in the previous step. */
		snprintf(datasock.sun_path, sizeof(datasock.sun_path), "%s/.%05d-%05d", vde_url, pid, sockno++);
		res=bind(fddata, (struct sockaddr *) &datasock, sizeof (datasock));
	}
	while (res < 0 && errno == EADDRINUSE);

	/* It didn't work. So we cycle on the fallback directories until we find a
	 * suitable one (or the list ends). */
	if (res < 0)
	{
		int i;
		for (i = 0, res = -1, sockno = 0; fallback_dirname[i] && (res != 0); i++)
		{
			memset(datasock.sun_path, 0, sizeof(datasock.sun_path));
			do
			{
				sprintf(datasock.sun_path, "%s/vde.%05d-%05d", fallback_dirname[i], pid, sockno++);
				res = bind(fddata, (struct sockaddr *) &datasock, sizeof (datasock));
			}
			while (res < 0 && errno == EADDRINUSE);
		}
	}

	/* Nothing worked, so cleanup and return with an error. */
	if (res < 0)
		goto abort;

	if (group) {
		struct group *gs;
		gid_t gid;
		if ((gs=getgrnam(group)) == NULL)
			gid=atoi(group);
		else
			gid=gs->gr_gid;
		if (chown(datasock.sun_path, -1, gid) < 0)
			goto abort_deletesock;
	} else {
		/* when group is not defined, set permission for the reverse channel */
		struct stat ctlstat;
		/* if no permission gets "voluntarily" granted to the socket */
		if ((mode & 077) == 0) {
			if (stat(sockun.sun_path, &ctlstat) == 0) {
				/* if the switch is owned by root or by the same user it should
					 work 0700 */
				if (ctlstat.st_uid != 0 && ctlstat.st_uid != geteuid()) {
					/* try to change the group ownership to the same of the switch */
					/* this call succeeds if the vde user and the owner of the switch
						 belong to the group */
					if (chown(datasock.sun_path, -1, ctlstat.st_gid) == 0)
						mode |= 070;
					else
						mode |= 077;
				}
			}
		}
	}
	chmod(datasock.sun_path, mode);
	req.sock = datasock;

	if (send(fdctl, &req, sizeof(req) - MAXDESCR + strlen(req.description), 0) < 0) 
		goto abort_deletesock;

	if (recv(fdctl, &datasock, sizeof(struct sockaddr_un), 0) <= 0)
		goto abort_deletesock;

	if (connect(fddata, (struct sockaddr *)&datasock, sizeof(struct sockaddr_un)) < 0)
		goto abort_deletesock;

	chmod(datasock.sun_path, mode);

	if ((newconn=calloc(1, sizeof(struct vde_vde_conn)))==NULL)
	{
		errno=ENOMEM;
		goto abort_deletesock;
	}

	newconn->fdctl=fdctl;
	newconn->fddata=fddata;
	unlink(req.sock.sun_path);

	return (VDECONN *)newconn;

abort_deletesock:
	unlink(req.sock.sun_path);	
abort:
	if (fdctl >= 0) close(fdctl);
	if (fddata >= 0) close(fddata);
	return NULL;
}

static ssize_t vde_vde_recv(VDECONN *conn, void *buf, size_t len, int flags)
{
	struct vde_vde_conn *vde_conn = (struct vde_vde_conn *)conn;
	return recv(vde_conn->fddata, buf, len, 0);
}

static ssize_t vde_vde_send(VDECONN *conn, const void *buf, size_t len, int flags)
{
	struct vde_vde_conn *vde_conn = (struct vde_vde_conn *)conn;
	return send(vde_conn->fddata, buf, len, 0);
}

static int vde_vde_datafd(VDECONN *conn)
{
	struct vde_vde_conn *vde_conn = (struct vde_vde_conn *)conn;
	return vde_conn->fddata;
}

static int vde_vde_ctlfd(VDECONN *conn)
{
	struct vde_vde_conn *vde_conn = (struct vde_vde_conn *)conn;
	return vde_conn->fdctl;
}

static int vde_vde_close(VDECONN *conn)
{
	struct vde_vde_conn *vde_conn = (struct vde_vde_conn *)conn;
	close(vde_conn->fddata);
	close(vde_conn->fdctl);
	free(vde_conn);

	return 0;
}
