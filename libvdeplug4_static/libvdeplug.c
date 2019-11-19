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

/* enough char to store an int type */
#define ENOUGH(type) ((CHAR_BIT * sizeof(type) - 1) / 3 + 2)
#define ENOUGH_OCTAL(type) ((CHAR_BIT * sizeof(type) + 2) / 3)
/* vde_plug --descr xx --port2 xx --mod2 xx --group2 xx seqpacket://NN vdeurl (NULL) */
#define VDE_MAX_ARGC 12
#define SEQPACKET_HEAD "seqpacket://"
#define SEQPACKET_HEAD_LEN (sizeof(SEQPACKET_HEAD) - 1)
#define DEFAULT_DESCRIPTION "libvdeplug"
#define CHILDSTACKSIZE 4096

#define err_goto(err, label) do { \
	(err) = errno; \
	goto label; \
} while(0)

struct child_data {
  char **argv;
  int fd;
};

static int child(void *arg) {
  struct child_data *data = arg;
	int err;
  execvp(data->argv[0], data->argv);
	err = errno;
	write(data->fd, &err, sizeof(err));
  close(data->fd);
  return 0;
}

VDECONN *vde_open_real(char *given_vde_url, char *descr,int interface_version,
		    struct vde_open_args *open_args)
{
	int sv[2];
	struct vdeconn *conn;
	char *description = (descr != NULL && *descr != 0) ? descr : DEFAULT_DESCRIPTION;
	char *vde_url = (given_vde_url == NULL) ? "" : given_vde_url;
	char seqpacketurl[SEQPACKET_HEAD_LEN + ENOUGH(int) + 1] = SEQPACKET_HEAD;
	char port_str[ENOUGH(int) + 1];
	char mode_str[ENOUGH_OCTAL(mode_t) + 2];
	char *argv[VDE_MAX_ARGC] = {"vde_plug", "--descr", description, seqpacketurl, vde_url, NULL};
	int argc = 3;
	int rv, err;
	struct child_data data;
  char childstack[CHILDSTACKSIZE];
	int fds[2];
	int pid;

	if (open_args != NULL) {
		if (open_args->port != 0) {
			snprintf(port_str, ENOUGH(int) + 1, "%d", open_args->port);
			argv[argc++] = "--port2";
			argv[argc++] = port_str;
		}
		if (open_args->group != 0) {
			argv[argc++] = "--group2";
			argv[argc++] = open_args->group;
		}
		if (open_args->mode != 0) {
			snprintf(mode_str, ENOUGH_OCTAL(mode_t) + 2, "0%o", open_args->mode);
			argv[argc++] = "--mod2";
			argv[argc++] = mode_str;
		}
	}
	argv[argc++] = seqpacketurl;
	argv[argc++] = vde_url;
	argv[argc++] = NULL;

	/* synch socketpair: fds[0] is for the parent, fds[1] is
		 close_on_exec inherited by the child */
	rv = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	if (rv < 0)
		err_goto(err, leave);
	data.argv = argv;
  data.fd = fds[1];

  rv = fcntl(fds[1], F_SETFD, FD_CLOEXEC);
	if (rv < 0)
		err_goto(err, close_fds);

	/* This socketpair is for vde packets: sv[0] is for the parent (e.g. User-Mode Linux)
		 sv[1] is forthe helper command (vde_plug) */
	rv = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
	if (rv < 0)
		err_goto(err, close_fds);

  rv = fcntl(sv[0], F_SETFD, FD_CLOEXEC);
	if (rv < 0)
		err_goto(err, close_sv);

	conn = (VDECONN *) malloc(sizeof(VDECONN));
	if (conn == NULL)
		err_goto(err, close_sv);

	snprintf(seqpacketurl + SEQPACKET_HEAD_LEN, SEQPACKET_HEAD_LEN, "%d", sv[1]);

	/* use clone instead of fork. User-mode linux cannot fork */
	pid = clone(child, (void *) (childstack + CHILDSTACKSIZE),
      CLONE_VM, &data);
	if (pid < 0)
		err_goto(err, free_conn);

	/* close the descriptors used by the child */
	close(fds[1]);
	close(sv[1]);
	conn->fddata = sv[0];

	/* wait for child's execvp */
	rv = read(fds[0], &err, sizeof(err));
	close(fds[0]);
	if (rv > 0) {
		close(sv[0]);
		free(conn);
		errno = err;
		return NULL;
	} else
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
	errno = err;
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
