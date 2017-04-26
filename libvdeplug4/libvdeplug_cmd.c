/*
 * libvdeplug - A library to connect to a VDE Switch.
 * Copyright (C) 2017 Renzo Davoli, University of Bologna
 *
 * Stream vde to a command
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
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <execs.h>
#include "libvdeplug_mod.h"

static VDECONN *vde_cmd_open(char *given_vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_cmd_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_cmd_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_cmd_datafd(VDECONN *conn);
static int vde_cmd_ctlfd(VDECONN *conn);
static int vde_cmd_close(VDECONN *conn);

struct vdeplug_module vdeplug_ops={
	.vde_open_real=vde_cmd_open,
	.vde_recv=vde_cmd_recv,
	.vde_send=vde_cmd_send,
	.vde_datafd=vde_cmd_datafd,
	.vde_ctlfd=vde_cmd_ctlfd,
	.vde_close=vde_cmd_close};

struct vde_cmd_conn {
	void *handle;
	struct vdeplug_module *module;
	char *cmdstring;
	pid_t cmd_pid;
	int cmd_fd[2];
};

static VDECONN *vde_cmd_open(char *cmdstring, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	struct vde_cmd_conn *newconn;

	if ((newconn=calloc(1,sizeof(struct vde_cmd_conn)))==NULL)
	{
		errno=ENOMEM;
		goto abort;
	}
	newconn->cmdstring = strdup(cmdstring);
	if ((newconn->cmd_pid = coprocsp(cmdstring, newconn->cmd_fd)) < 0)
		goto free_abort;
	return (VDECONN *)newconn;
free_abort:
	free(newconn);

abort:
	return NULL;
}

static ssize_t vde_cmd_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	struct vde_cmd_conn *vde_conn = (struct vde_cmd_conn *)conn;
	unsigned char header[2];
	unsigned int pktlen;
	ssize_t rv;
	struct pollfd pollok = {vde_conn->cmd_fd[0], POLLIN, 0};
	if ((rv = read(vde_conn->cmd_fd[0], header, 2)) != 2)
		goto error;
 	pktlen = (header[0]<<8) + header[1];
	if (pktlen > VDE_ETHBUFSIZE)
		goto error;
	if (poll(&pollok,1,0) <= 0)
		goto error;
	if (pktlen <= len) {
		if ((rv = read(vde_conn->cmd_fd[0], buf, pktlen)) != pktlen)
			goto error;
		return rv;
	} else {
		ssize_t taillen = pktlen - len;
		unsigned char tail[taillen];
		struct iovec iov[2]={{buf, len}, {tail, taillen}};
		if ((rv = readv(vde_conn->cmd_fd[0], iov, 2)) != pktlen)
			goto error;
		return len;
	}
error:
	if (rv < 0) {
		return rv;
	} else if (rv == 0) { // the command terminated
		int fd[2];
		int status;
		pipe(fd);
		dup2(fd[0], vde_conn->cmd_fd[0]);
		dup2(fd[1], vde_conn->cmd_fd[1]);
		waitpid(vde_conn->cmd_pid, &status, WNOHANG); /* discard exit status */
		fprintf(stderr, "VDE terminated: cmd://%s\n",vde_conn->cmdstring);
		return rv;
	} else {
		errno = EAGAIN;
		return 1;
	}
}

static ssize_t vde_cmd_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	struct vde_cmd_conn *vde_conn = (struct vde_cmd_conn *)conn;
	if (len <= VDE_ETHBUFSIZE) {
		unsigned char header[2];
		struct iovec iov[2]={{header,2},{(void *)buf,len}};
		header[0]=len >> 8;
		header[1]=len & 0xff;
		return writev(vde_conn->cmd_fd[1],iov,2);
	} else
		return 0;
}

static int vde_cmd_datafd(VDECONN *conn)
{
	struct vde_cmd_conn *vde_conn = (struct vde_cmd_conn *)conn;
	return vde_conn->cmd_fd[0];
}

static int vde_cmd_ctlfd(VDECONN *conn)
{
	return -1;
}

static int vde_cmd_close(VDECONN *conn)
{
	struct vde_cmd_conn *vde_conn = (struct vde_cmd_conn *)conn;
	int status;
	close(vde_conn->cmd_fd[1]);
	close(vde_conn->cmd_fd[0]);
	kill(SIGTERM, vde_conn->cmd_pid);
	waitpid(vde_conn->cmd_pid, &status, 0); /* discard exit status */
	if (vde_conn->cmdstring)
		free(vde_conn->cmdstring);
	free(vde_conn);
	return 0;
}
