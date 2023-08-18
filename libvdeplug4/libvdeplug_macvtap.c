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
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <libvdeplug.h>
#include <errno.h>
#include "libvdeplug_mod.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

static VDECONN *vde_macvtap_open(char *given_vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_macvtap_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_macvtap_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_macvtap_datafd(VDECONN *conn);
static int vde_macvtap_ctlfd(VDECONN *conn);
static int vde_macvtap_close(VDECONN *conn);

struct vdeplug_module vdeplug_ops={
	.vde_open_real=vde_macvtap_open,
	.vde_recv=vde_macvtap_recv,
	.vde_send=vde_macvtap_send,
	.vde_datafd=vde_macvtap_datafd,
	.vde_ctlfd=vde_macvtap_ctlfd,
	.vde_close=vde_macvtap_close};

struct vde_macvtap_conn {
	void *handle;
	struct vdeplug_module *module;
	int fddata;
};

static int get_ifindex(char *iface) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct ifreq ifr = {0};
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
		return -1;
	else
		return ifr.ifr_ifindex;
}

static VDECONN *vde_macvtap_open(char *given_vde_url, char *descr, int interface_version,
		struct vde_open_args *open_args)
{
	struct ifreq ifr;
	int fddata=-1;
	struct vde_macvtap_conn *newconn;
	int ifindex = get_ifindex(given_vde_url);
	if (ifindex < 0)
		return NULL;
	size_t tap_path_len = snprintf(NULL, 0, "/dev/tap%d", ifindex) + 1;
	char tap_path[tap_path_len];
	snprintf(tap_path, tap_path_len, "/dev/tap%d", ifindex);

	if((fddata = open(tap_path, O_RDWR)) < 0)
		goto abort;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if(ioctl(fddata, TUNSETIFF, (void *) &ifr) < 0)
		goto abort;

	if ((newconn=calloc(1,sizeof(struct vde_macvtap_conn)))==NULL) {
		errno=ENOMEM;
		goto abort;
	}

	newconn->fddata=fddata;

	return (VDECONN *)newconn;

abort:
	if (fddata >= 0) close(fddata);
	return NULL;
}

static ssize_t vde_macvtap_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	struct vde_macvtap_conn *vde_conn = (struct vde_macvtap_conn *)conn;
	return read(vde_conn->fddata,buf,len);
}

static ssize_t vde_macvtap_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	struct vde_macvtap_conn *vde_conn = (struct vde_macvtap_conn *)conn;
	return write(vde_conn->fddata,buf,len);
}

static int vde_macvtap_datafd(VDECONN *conn)
{
	struct vde_macvtap_conn *vde_conn = (struct vde_macvtap_conn *)conn;
	return vde_conn->fddata;
}

static int vde_macvtap_ctlfd(VDECONN *conn)
{
	return -1;
}

static int vde_macvtap_close(VDECONN *conn)
{
	struct vde_macvtap_conn *vde_conn = (struct vde_macvtap_conn *)conn;
	close(vde_conn->fddata);
	free(vde_conn);
	return 0;
}
