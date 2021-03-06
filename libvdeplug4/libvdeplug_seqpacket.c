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
#include <string.h>
#include <unistd.h>
#include <libvdeplug.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include "libvdeplug_mod.h"

static VDECONN *vde_seqpacket_open(char *vde_url, char *descr, int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_seqpacket_recv(VDECONN *conn, void *buf, size_t len, int flags);
static ssize_t vde_seqpacket_send(VDECONN *conn, const void *buf, size_t len, int flags);
static int vde_seqpacket_datafd(VDECONN *conn);
static int vde_seqpacket_ctlfd(VDECONN *conn);
static int vde_seqpacket_close(VDECONN *conn);

struct vdeplug_module vdeplug_ops={
	.vde_open_real=vde_seqpacket_open,
	.vde_recv=vde_seqpacket_recv,
	.vde_send=vde_seqpacket_send,
	.vde_datafd=vde_seqpacket_datafd,
	.vde_ctlfd=vde_seqpacket_ctlfd,
	.vde_close=vde_seqpacket_close};

struct vde_seqpacket_conn {
	void *handle;
	struct vdeplug_module *module;
	int fddata;
};

static VDECONN *vde_seqpacket_open(char *vde_url, char *descr, int interface_version,
		struct vde_open_args *open_args)
{
	long fddata=-1;
	struct vde_seqpacket_conn *newconn;

	errno = 0;
	fddata = strtol(vde_url, NULL, 0);

	if (errno != 0)
		return NULL;

	if (fddata < 0) {
		errno = EINVAL;
		return NULL;
	}

	if ((newconn = calloc(1, sizeof(struct vde_seqpacket_conn))) == NULL) {
		close(fddata);
		errno = ENOMEM;
		return NULL;
	}
	newconn->fddata=fddata;

	return (VDECONN *)newconn;
}

static ssize_t vde_seqpacket_recv(VDECONN *conn, void *buf, size_t len, int flags)
{
	struct vde_seqpacket_conn *vde_conn = (struct vde_seqpacket_conn *)conn;
	return recv(vde_conn->fddata, buf, len, 0);
}

static ssize_t vde_seqpacket_send(VDECONN *conn, const void *buf, size_t len, int flags)
{
	struct vde_seqpacket_conn *vde_conn = (struct vde_seqpacket_conn *)conn;
	/* never send zero length packets */
	if (__builtin_expect(len > 0, 1))
		return send(vde_conn->fddata, buf, len, 0);
	else
		return len;
}

static int vde_seqpacket_datafd(VDECONN *conn)
{
	struct vde_seqpacket_conn *vde_conn = (struct vde_seqpacket_conn *)conn;
	return vde_conn->fddata;
}

static int vde_seqpacket_ctlfd(VDECONN *conn)
{
	return -1;
}

static int vde_seqpacket_close(VDECONN *conn)
{
	struct vde_seqpacket_conn *vde_conn = (struct vde_seqpacket_conn *)conn;
	close(vde_conn->fddata);
	free(vde_conn);

	return 0;
}
