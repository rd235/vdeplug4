/*
 * libvdeplug - A library to connect to a VDE Switch.
 * point to point link
 * Copyright (C) 2013-2025 Renzo Davoli, University of Bologna
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
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include "libvdeplug_mod.h"

#define UNIX_PATH_MAX 108
#define EPOLL_DATAFD 0
#define EPOLL_LISTENFD 1
#define ETH_HEADER_SIZE 14

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
	int datafd;
	int listenfd;
	int epollfd;
	char path[UNIX_PATH_MAX];
};

#define UNUSED(...) (void)(__VA_ARGS__)

static int get1byteack(int fd) {
	unsigned char err;
	struct pollfd pfd[] = {{fd, POLLIN, 0}};
	int ret = poll(pfd, 1, 2000);
	if (ret <= 0) {
		if (ret == 0) errno = ETIMEDOUT;
		return -1;
	}
	ret = recv(fd, &err, 1, 0);
	if (ret == 1) {
		if (err == 0) return 0;
		errno = err;
	} else if (ret == 0) 
		errno = EFAULT;
	return -1;
}

static int ptpconnect(struct vde_ptp_conn *conn) {
	int fd;
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX
	};
	memcpy(addr.sun_path, conn->path, UNIX_PATH_MAX);
	if (conn->datafd >= 0 || conn->listenfd >= 0)
		return errno = EISCONN, -1;
	if ((fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0)) < 0)
		return -1;
	for (;;) {
		if ((connect(fd, (const struct sockaddr *) &addr, sizeof(addr))) >= 0) {
			/* ck 1 byte ack */
			if (get1byteack(fd) < 0) {
				close(fd);
				return -1;
			}
			struct epoll_event ev = {
				.events = EPOLLIN | EPOLLHUP,
				.data.u32 = EPOLL_DATAFD
			};
			if ((epoll_ctl(conn->epollfd, EPOLL_CTL_ADD, fd, &ev)) < 0) {
				close(fd);
				return -1;
			}
			conn->datafd = fd;
			return 0;
		}
		if (errno == ENOENT) {
			if ((bind(fd, (const struct sockaddr *) &addr, sizeof(addr))) >= 0) {
				struct epoll_event ev = {
					.events = EPOLLIN | EPOLLHUP,
					.data.u32 = EPOLL_LISTENFD
				};
				if (listen(fd, 1) < 0) {
					close(fd);
					return -1;
				}
				if ((epoll_ctl(conn->epollfd, EPOLL_CTL_ADD, fd, &ev)) < 0) {
					close(fd);
					return -1;
				}
				conn->listenfd = fd;
				return 0;
			}
			if (errno == EADDRINUSE)
				continue;   // try again!
			if (errno == ECONNREFUSED) {
				unlink(conn->path);
				continue;
			}
		}
		return -1;
	}
	return 0;
}

static VDECONN *vde_ptp_open(char *given_vde_url, char *descr,int interface_version,
		    struct vde_open_args *open_args)
{
	struct vde_ptp_conn *newconn;
	if ((newconn = calloc(1,sizeof(struct vde_ptp_conn))) == NULL)
    goto abort;
	newconn->datafd = -1;
	newconn->listenfd = -1;
	if ((newconn->epollfd = epoll_create1(EPOLL_CLOEXEC)) < 0)
		goto abort_calloc;
	memset(newconn->path, 0, UNIX_PATH_MAX);
	snprintf(newconn->path, UNIX_PATH_MAX, "%s", given_vde_url);

	if (ptpconnect(newconn) < 0)
		goto abort_calloc;

	return (VDECONN *)newconn;

abort_calloc:
	free(newconn);
abort:
	return NULL;
}

static ssize_t vde_ptp_recv(VDECONN *conn, void *buf, size_t len, int flags)
{
	struct vde_ptp_conn *vde_conn = (struct vde_ptp_conn *)conn;
	struct epoll_event ev;
	int ret = epoll_wait(vde_conn->epollfd, &ev, 1, -1);
	if (ret == 1) {
		if (ev.data.u32 == EPOLL_DATAFD) {
			if (ev.events & EPOLLHUP) {
				close(vde_conn->datafd);
				epoll_ctl(vde_conn->epollfd, EPOLL_CTL_DEL, vde_conn->datafd, &ev);
				vde_conn->datafd = -1;
				if (vde_conn->listenfd < 0) {
					if (ptpconnect(vde_conn) < 0)
						return -1;
				}
			}
			if (ev.events & EPOLLIN) {
				return recv(vde_conn->datafd, buf, len, 0);
			}
		}
		if (ev.data.u32 == EPOLL_LISTENFD) {
			if (ev.events & EPOLLIN) {
				int fd = accept(vde_conn->listenfd, NULL, NULL);
				if (fd < 0)
					return -1;
				if (vde_conn->datafd >= 0) {
					unsigned char err = EISCONN;
					send(fd, &err, 1, 0);
					close(fd); // 1 char ack
				} else {
					char err = 0;
					send(fd, &err, 1, 0);
					ev.events = EPOLLIN | EPOLLHUP;
					ev.data.u32 = EPOLL_DATAFD;
					if ((epoll_ctl(vde_conn->epollfd, EPOLL_CTL_ADD, fd, &ev)) < 0) {
						close(fd);
						return -1;
					}
					vde_conn->datafd = fd;
				}
			}
		}
	}
	return 1;
}

static ssize_t vde_ptp_send(VDECONN *conn, const void *buf, size_t len, int flags)
{
	struct vde_ptp_conn *vde_conn = (struct vde_ptp_conn *)conn;
	if (vde_conn->datafd >= 0 && len >= ETH_HEADER_SIZE)
		return send(vde_conn->datafd, buf, len, MSG_DONTWAIT);
	return len; // drop pckt if not connected
}

static int vde_ptp_datafd(VDECONN *conn)
{
	struct vde_ptp_conn *vde_conn = (struct vde_ptp_conn *)conn;
	return vde_conn->epollfd;
}

static int vde_ptp_ctlfd(VDECONN *conn)
{
	return -1;
}

static int vde_ptp_close(VDECONN *conn)
{
	struct vde_ptp_conn *vde_conn = (struct vde_ptp_conn *)conn;
	if (vde_conn->listenfd >= 0) {
		unlink(vde_conn->path);
		close(vde_conn->listenfd);
	}
	if (vde_conn->datafd >= 0)
		close(vde_conn->datafd);
	close(vde_conn->epollfd);
	free(vde_conn);

	return 0;
}
