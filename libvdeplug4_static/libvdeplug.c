/*
 * libvdeplug - A library to connect to a VDE Switch.
 * static library (using vde_plug as a helper)
 * Copyright (C) 2019 Renzo Davoli, University of Bologna
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sched.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <libvdeplug.h>

struct vdeconn {
	int fddata;
};

#define ENOUGH(type) ((CHAR_BIT * sizeof(type) - 1) / 3 + 2)
#define SEQPACKET_HEAD "seqpacket://"
#define SEQPACKET_HEAD_LEN (sizeof(SEQPACKET_HEAD) - 1)
#define DEFAULT_DESCRIPTION "libvdeplug"
#define CHILDSTACKSIZE 4096

struct child_data {
  char **argv;
  int fd;
};

static int child(void *arg) {
  struct child_data *data = arg;
  execvp(data->argv[0], data->argv);
  close(data->fd);
  return 0;
}

VDECONN *vde_open_real(char *given_vde_url, char *descr,int interface_version,
		    struct vde_open_args *open_args)
{
	int sv[2];
	struct vdeconn *conn;
	char *description = (descr != NULL && *descr != 0) ? descr : DEFAULT_DESCRIPTION;
	char seqpacketurl[SEQPACKET_HEAD_LEN + ENOUGH(int) + 1] = SEQPACKET_HEAD;
	char *argv[] = {"vde_plug", "--descr", description, seqpacketurl, 
		(given_vde_url == NULL) ? "" : given_vde_url, NULL};
	int rv;
	struct child_data data;
  char childstack[CHILDSTACKSIZE];
	int fds[2];
	int pid;

	rv = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	if (rv < 0)
		goto leave;
	data.argv = argv;
  data.fd = fds[1];

  rv = fcntl(fds[1], F_SETFD, FD_CLOEXEC);
	if (rv < 0)
		goto close_fds;

	rv = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
	if (rv < 0) 
		goto close_fds;

  rv = fcntl(sv[0], F_SETFD, FD_CLOEXEC);
	if (rv < 0)
		goto close_sv;

	conn = (VDECONN *) malloc(sizeof(VDECONN));
	if (conn == NULL)
		goto close_sv;

	snprintf(seqpacketurl + SEQPACKET_HEAD_LEN, SEQPACKET_HEAD_LEN, "%d", sv[1]);

	/* use clone instead of fork. User-mode linux cannot fork */
	pid = clone(child, (void *) childstack + CHILDSTACKSIZE,
      CLONE_VM, &data);
	if (pid < 0)
		goto free_conn;

	close(fds[1]);
	close(sv[1]);
	conn->fddata = sv[0];

	/* wait for child's execvp */
	/* TODO it can return an error code if execvp fails*/
	read(fds[0], &rv, sizeof(rv));

	close(fds[0]);

	return conn;

free_conn:
	free(conn);
close_sv:
	close(sv[0]);
	close(sv[1]);
close_fds:
	close(fds[0]);
	close(fds[1]);
leave:
	return NULL;
}

ssize_t vde_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	if (__builtin_expect(conn!=0,1))
		return recv(conn->fddata,buf,len,0);
	else {
		errno=EBADF;
		return -1;
	}
}

ssize_t vde_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	if (__builtin_expect(conn!=0,1)) {
		/* never send zero length packets */
		if (__builtin_expect(len > 0, 1))
			return send(conn->fddata,buf,len,0);
		else
			return len;
	} else {
		errno=EBADF;
		return -1;
	}
}

int vde_datafd(VDECONN *conn)
{
	if (__builtin_expect(conn!=0,1))
		return conn->fddata;
	else {
		errno=EBADF;
		return -1;
	}
}

int vde_ctlfd(VDECONN *conn)
{
	return -1;
}

int vde_close(VDECONN *conn)
{
	if (__builtin_expect(conn!=0,1)) {
		return close(conn->fddata);
	} else {
		errno=EBADF;
		return -1;
	}
}
