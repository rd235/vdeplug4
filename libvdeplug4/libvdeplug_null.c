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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <libvdeplug.h>
#include <errno.h>
#include <sys/eventfd.h>
#include "libvdeplug_mod.h"

static VDECONN *vde_null_open(char *given_vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_null_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_null_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_null_datafd(VDECONN *conn);
static int vde_null_ctlfd(VDECONN *conn);
static int vde_null_close(VDECONN *conn);

struct vdeplug_module vdeplug_ops={
	.vde_open_real=vde_null_open,
	.vde_recv=vde_null_recv,
	.vde_send=vde_null_send,
	.vde_datafd=vde_null_datafd,
	.vde_ctlfd=vde_null_ctlfd,
	.vde_close=vde_null_close};

struct vde_null_conn {
	void *handle;
	struct vdeplug_module *module;
	int fddata;
};

static VDECONN *vde_null_open(char *given_vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	struct vde_null_conn *newconn;
	int fddata = eventfd(0, EFD_CLOEXEC);
	if (fddata < 0)
		goto abort;

	if ((newconn=calloc(1,sizeof(struct vde_null_conn)))==NULL) {
		errno=ENOMEM;
		goto abort;
	}

	newconn->fddata=fddata;

	return (VDECONN *)newconn;
abort:
	if (fddata >= 0) close(fddata);
	return NULL;
}

static ssize_t vde_null_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	//struct vde_null_conn *vde_conn = (struct vde_null_conn *)conn;
	return 1;
}

static ssize_t vde_null_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	//struct vde_null_conn *vde_conn = (struct vde_null_conn *)conn;
	return len;
}

static int vde_null_datafd(VDECONN *conn)
{
	struct vde_null_conn *vde_conn = (struct vde_null_conn *)conn;
	return vde_conn->fddata;
}

static int vde_null_ctlfd(VDECONN *conn)
{
	return -1;
}

static int vde_null_close(VDECONN *conn)
{
	struct vde_null_conn *vde_conn = (struct vde_null_conn *)conn;
	close(vde_conn->fddata);
	free(vde_conn);
	return 0;
}
