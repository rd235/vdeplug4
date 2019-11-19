/*
 * libvdeplug - A library to connect to a VDE Switch.
 * Copyright (C) 2013-2016 Renzo Davoli, University of Bologna
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
#include "libvdeplug_mod.h"

static VDECONN *vde_ptp_open(char *given_vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_ptp_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_ptp_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_ptp_datafd(VDECONN *conn);
static int vde_ptp_ctlfd(VDECONN *conn);
static int vde_ptp_close(VDECONN *conn);

struct vdeplug_module vdeplug_ops={
	.vde_open_real=vde_ptp_open,
	.vde_recv=vde_ptp_recv,
	.vde_send=vde_ptp_send,
	.vde_datafd=vde_ptp_datafd,
	.vde_ctlfd=vde_ptp_ctlfd,
	.vde_close=vde_ptp_close};

struct vde_ptp_conn {
	void *handle;
	struct vdeplug_module *module;
	int fddata;
	char *inpath;
	struct sockaddr *outsock;
	size_t outlen;
};

#define UNUSED(...) (void)(__VA_ARGS__)

static VDECONN *vde_ptpf_open(char *given_vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	int port=0;
	char *group=NULL;
	mode_t mode=0700;
	int fddata=-1;
	struct sockaddr_un sockun;
	struct sockaddr_un sockout;
	struct stat sockstat;
	int res;
	struct vde_ptp_conn *newconn;

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

	UNUSED(port);

	memset(&sockun, 0, sizeof(sockun));
	if((fddata = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)) < 0)
		goto abort;
	sockun.sun_family = AF_UNIX;
	snprintf(sockun.sun_path, sizeof(sockun.sun_path)-1, "%s", given_vde_url);
	/* the socket already exists */
	if(stat(sockun.sun_path,&sockstat) == 0) {
		if (S_ISSOCK(sockstat.st_mode)) {
			/* the socket is already in use */
			res = connect(fddata, (struct sockaddr *) &sockun, sizeof(sockun));
			if (res >= 0) {
				errno = EADDRINUSE;
				goto abort;
			}
			if (errno == ECONNREFUSED)
				unlink(sockun.sun_path);
		}
	}
	res = bind(fddata, (struct sockaddr *) &sockun, sizeof(sockun));
	if (res < 0)
		goto abort;
	memset(&sockout, 0, sizeof(sockun));
	sockout.sun_family = AF_UNIX;
	snprintf(sockout.sun_path, sizeof(sockun.sun_path), "%s+", given_vde_url);
	if (group) {
		struct group *gs;
		gid_t gid;
		if ((gs=getgrnam(group)) == NULL)
			gid=atoi(group);
		else
			gid=gs->gr_gid;
		if (chown(sockun.sun_path,-1,gid) < 0)
			goto abort;
	}
	chmod(sockun.sun_path,mode);

	if ((newconn=calloc(1,sizeof(struct vde_ptp_conn)))==NULL)
	{
		errno=ENOMEM;
		goto abort;
	}

	newconn->fddata=fddata;
	newconn->inpath=strdup(sockun.sun_path);
	newconn->outlen = sizeof(struct sockaddr_un);
	newconn->outsock=malloc(newconn->outlen);
	memcpy(newconn->outsock,&sockout,sizeof(struct sockaddr_un));

	return (VDECONN *)newconn;

abort:
	if (fddata >= 0) close(fddata);
	return NULL;
}

static VDECONN *vde_ptpm_open(char *given_vde_url, char *descr,int interface_version,
		    struct vde_open_args *open_args)
{
	int port=0;
	char *group=NULL;
	mode_t mode=0700;
	int fddata=-1;
	struct sockaddr_un sockun;
	struct sockaddr_un sockout;
	struct stat sockstat;
	int res;
	struct vde_ptp_conn *newconn;

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

	UNUSED(port);

	memset(&sockun, 0, sizeof(sockun));
	memset(&sockout, 0, sizeof(sockun));
	sockun.sun_family = AF_UNIX;
	sockout.sun_family = AF_UNIX;
	if((fddata = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)) < 0)
		goto abort;
	snprintf(sockout.sun_path, sizeof(sockout.sun_path)-1, "%s", given_vde_url);
	res = connect(fddata, (struct sockaddr *) &sockout, sizeof(sockout));
	if (res < 0)
		goto abort;
	snprintf(sockun.sun_path, sizeof(sockun.sun_path)-1, "%s+", given_vde_url);
	/* the socket already exists */
	if(stat(sockun.sun_path,&sockstat) == 0) {
		if (S_ISSOCK(sockstat.st_mode)) {
			/* the socket is already in use */
			res = connect(fddata, (struct sockaddr *) &sockun, sizeof(sockun));
			if (res >= 0) {
				errno = EADDRINUSE;
				goto abort;
			}
			if (errno == ECONNREFUSED)
				unlink(sockun.sun_path);
		}
	}
	res = bind(fddata, (struct sockaddr *) &sockun, sizeof(sockun));
	if (res < 0)
		goto abort;
	if (group) {
		struct group *gs;
		gid_t gid;
		if ((gs=getgrnam(group)) == NULL)
			gid=atoi(group);
		else
			gid=gs->gr_gid;
		if (chown(sockun.sun_path,-1,gid) < 0)
			goto abort;
	}
	chmod(sockun.sun_path,mode);

	if ((newconn=calloc(1,sizeof(struct vde_ptp_conn)))==NULL)
	{
		errno=ENOMEM;
		goto abort;
	}

	newconn->fddata=fddata;
	newconn->inpath=strdup(sockun.sun_path);
	newconn->outlen = sizeof(struct sockaddr_un);
	newconn->outsock=malloc(newconn->outlen);
	memcpy(newconn->outsock,&sockout,sizeof(struct sockaddr_un));

	return (VDECONN *)newconn;

abort:
	if (fddata >= 0) close(fddata);
	return NULL;
}

static VDECONN *vde_ptp_open(char *given_vde_url, char *descr,int interface_version,
		    struct vde_open_args *open_args)
{
	VDECONN *rv;
	rv=vde_ptpf_open(given_vde_url, descr, interface_version, open_args);
	if (!rv)
		rv=vde_ptpm_open(given_vde_url, descr, interface_version, open_args);
	return rv;
}

static ssize_t vde_ptp_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	struct vde_ptp_conn *vde_conn = (struct vde_ptp_conn *)conn;
#ifdef CONNECTED_P2P
	ssize_t retval;
	if (__builtin_expect(((retval=recv(vde_conn->fddata,buf,len,0)) > 0), 1))
		return retval;
	else {
		if (retval == 0 && vde_conn->outsock != NULL) {
			static struct sockaddr unspec={AF_UNSPEC};
			connect(vde_conn->fddata,&unspec,sizeof(unspec));
		}
		return retval;
	}
#else
	return recv(vde_conn->fddata,buf,len,0);
#endif
}

static ssize_t vde_ptp_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	struct vde_ptp_conn *vde_conn = (struct vde_ptp_conn *)conn;
#ifdef CONNECTED_P2P
	ssize_t retval;
	if (__builtin_expect(((retval=send(vde_conn->fddata,buf,len,0)) >= 0),1))
		return retval;
	else {
		if (__builtin_expect(errno == ENOTCONN || errno == EDESTADDRREQ,0)) {
			if (__builtin_expect(vde_conn->outsock != NULL,1)) {
				connect(vde_conn->fddata, vde_conn->outsock,vde_conn->outlen);
				return send(vde_conn->fddata,buf,len,0);
			} else
				return retval;
		} else
			return retval;
	}
#else
	return sendto(vde_conn->fddata,buf,len,0, vde_conn->outsock,vde_conn->outlen);
#endif
}

static int vde_ptp_datafd(VDECONN *conn)
{
	struct vde_ptp_conn *vde_conn = (struct vde_ptp_conn *)conn;
	return vde_conn->fddata;
}

static int vde_ptp_ctlfd(VDECONN *conn)
{
	return -1;
}

static int vde_ptp_close(VDECONN *conn)
{
	struct vde_ptp_conn *vde_conn = (struct vde_ptp_conn *)conn;
	close(vde_conn->fddata);
	if (vde_conn->inpath != NULL) {
		unlink(vde_conn->inpath);
		free(vde_conn->inpath);
	}
	if (vde_conn->outsock != NULL)
		free(vde_conn->outsock);
	free(vde_conn);

	return 0;
}
