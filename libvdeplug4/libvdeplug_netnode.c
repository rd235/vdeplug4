/*
 * libvdeplug - A library to connect to a VDE Switch.
 * Copyright (C) 2017 Renzo Davoli, University of Bologna
 *
 * libvdeplug_netnode.c common implementation of a networking node as a vdeplug plugin.
 * a netnode supports the connection of a virtual machine, namespace, wire-end (here named host) 
 * to several nodes. 
 * this module provides the following services:
 *     - hub: deliver packets to all the nodes but the sender (including the host)
 *     - multi: deliver packets from the host to all the connected nodes,
 *              but packets from the connected nodes to the host only.
 *     - bundling: deliver packets from the host to one connected node (in round robin manner),
 *              and packets from any of the connected nodes to the host only.
 *     - switch: it is an ethernet switch connecting all the nodes including the host.
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
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <libgen.h>

#include <libvdeplug.h>
#include "libvdeplug_mod.h"

#define SWITCH
#define SWITCH_MAGIC 0xfeedface
#define REQBUFLEN 256
#define PORTTAB_STEP 4
#define STDHASHSIZE 256
#define STDEXPIRETIME 120
#define STDMODE 0600
#define STDDIRMODE 02700
#define STDPATH "/tmp/vdenode_"
#define HOSTFAKEFD -1

enum request_type { REQ_NEW_CONTROL, REQ_NEW_PORT0 };

struct request_v3 {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
	struct sockaddr_un sock;
	char description[];
} __attribute__((packed));

static VDECONN *vde_hub_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static VDECONN *vde_multi_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static VDECONN *vde_switch_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static VDECONN *vde_bonding_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_netnode_recv(VDECONN *conn, void *buf, size_t len, int flags);
static ssize_t vde_netnode_send(VDECONN *conn, const void *buf, size_t len, int flags);
static int vde_netnode_datafd(VDECONN *conn);
static int vde_netnode_ctlfd(VDECONN *conn);
static int vde_netnode_close(VDECONN *conn);

struct vdeplug_module vdeplug_hub_ops={
	.vde_open_real=vde_hub_open,
	.vde_recv=vde_netnode_recv,
	.vde_send=vde_netnode_send,
	.vde_datafd=vde_netnode_datafd,
	.vde_ctlfd=vde_netnode_ctlfd,
	.vde_close=vde_netnode_close};

struct vdeplug_module vdeplug_multi_ops={
	.vde_open_real=vde_multi_open,
	.vde_recv=vde_netnode_recv,
	.vde_send=vde_netnode_send,
	.vde_datafd=vde_netnode_datafd,
	.vde_ctlfd=vde_netnode_ctlfd,
	.vde_close=vde_netnode_close};

struct vdeplug_module vdeplug_switch_ops={
	.vde_open_real=vde_switch_open,
	.vde_recv=vde_netnode_recv,
	.vde_send=vde_netnode_send,
	.vde_datafd=vde_netnode_datafd,
	.vde_ctlfd=vde_netnode_ctlfd,
	.vde_close=vde_netnode_close};

struct vdeplug_module vdeplug_bonding_ops={
	.vde_open_real=vde_bonding_open,
	.vde_recv=vde_netnode_recv,
	.vde_send=vde_netnode_send,
	.vde_datafd=vde_netnode_datafd,
	.vde_ctlfd=vde_netnode_ctlfd,
	.vde_close=vde_netnode_close};

enum netnode_type { HUBNODE, MULTINODE, SWITCHNODE, BONDINGNODE };

struct vde_netnode_conn {
	void *handle;
	struct vdeplug_module *module;
	enum netnode_type nettype;
	char *path;
	int epfd;
	int ctl_fd;
	mode_t mode;
	uint64_t *porttab;
	int porttablen, porttabmax;
	struct vde_hashtable *hashtable;
	int expiretime;
	int lastbonding;
};

/* porttab management. A port is a uint64_t.
	 porttab_add adds an element in the array conn->porttab. It reallocs the
	 array if there is no space for the new elements (it adds PORTTAB_STEP elements).

	 porttab_del deletes an element from conn->porttab. The valid elements of the
	 array are kept contiguous by swapping the last and the deleted element. 
	 */
void porttab_add(struct vde_netnode_conn *conn, uint64_t fd) {
	if (conn->porttablen == conn->porttabmax) {
		int porttabnewmax = conn->porttabmax + PORTTAB_STEP;
		uint64_t *portnewtab = realloc(conn->porttab, porttabnewmax * sizeof(uint64_t));
		if (portnewtab == NULL)
			return;
		conn->porttab = portnewtab;
		conn->porttabmax = porttabnewmax;
	}
	conn->porttab[conn->porttablen++]=fd;
}

void porttab_del(struct vde_netnode_conn *conn, uint64_t fd) {
	int i;
	for (i = 0; i < conn->porttablen; i++) {
		if (conn->porttab[i] == fd)
			break;
	}
	if (i < conn->porttablen) {
		conn->porttablen--;
		if (conn->porttablen > 0)
			conn->porttab[i] = conn->porttab[conn->porttablen];
	}
}

/* datasock_open: create a "control dir" compatible with vde-2 switches,
	 so that libvdeplug_vde can connect to this */
static int datasock_open(char *path, gid_t gid, int mode, int dirmode) {
	int connect_fd;
	struct sockaddr_un sun;
	int one = 1;
	if ((connect_fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0)
		goto abort;
	if (setsockopt(connect_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)) < 0)
		goto abort_connect_fd;
	if (mkdir(path, 02777) < 0)
		goto abort_connect_fd;
	if (gid >= 0 && chown(path, -1, gid) < 0)
		goto abort_mkdir;
	if (dirmode > 0 && chmod(path, dirmode) < 0)
		goto abort_mkdir;
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s/ctl",path);
	unlink(sun.sun_path); /* this should fail */
	if (bind(connect_fd, (struct sockaddr *) &sun, sizeof(sun)) < 0)
		goto abort_mkdir;
	if (gid >= 0 && chown(sun.sun_path, -1, gid) < 0)
		goto abort_unlink;
	if (mode > 0 && chmod(sun.sun_path, mode) < 0)
		goto abort_unlink;
	if (listen(connect_fd, 15) < 0)
		goto abort_unlink;
	return connect_fd;
abort_unlink:
	unlink(sun.sun_path);
abort_mkdir:
	rmdir(path);
abort_connect_fd:
	close(connect_fd);
abort:
	return -1;
}

static void datasock_close(char *path) {
	struct sockaddr_un sun;
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/ctl", path);
	unlink(sun.sun_path);
	rmdir(path);
}

/* accept a new connection */
static int ctl_in(char *path, int ctl_fd) {
	struct sockaddr_un addr;
	socklen_t len;
	int new;

	len = sizeof(addr);
	new = accept(ctl_fd, (struct sockaddr *) &addr, &len);
	return new;
}

/* open a new connection on an accepted connection */
static int conn_in(char *path, int conn_fd, mode_t mode) {
	char reqbuf[REQBUFLEN+1];
	struct request_v3 *req=(struct request_v3 *)reqbuf;
	int len;
	len = read(conn_fd, reqbuf, REQBUFLEN);
	/* backwards compatility: type can have embedded port# (type >> 8) */
	if (len > 0 && req->magic == SWITCH_MAGIC && req->version == 3 &&
			(req->type & 0xff) == REQ_NEW_CONTROL) {
		int data_fd;
		struct sockaddr_un sunc = req->sock;
		struct sockaddr_un sun;
		sun.sun_family = AF_UNIX;
		data_fd = socket(PF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		connect(data_fd, (struct sockaddr *) &sunc, sizeof(sunc));
		snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/fd%d", path, conn_fd);
		unlink(sun.sun_path);
		bind(data_fd, (struct sockaddr *) &sun, sizeof(sun));
		if (mode > 0)
			chmod(sun.sun_path, mode);
		write(conn_fd, &sun, sizeof(sun));
		return data_fd;
	}
	return -1;
}

/* compute the size needed to store a struct passwd */
static inline long sysconf_getpw_r_size_max(void) {
	long retval = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (retval < 0) retval = 16384;
	return retval;
}

/* compute the size needed to store a struct passwd */
static inline long sysconf_getgr_r_size_max(void) {
	long retval = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (retval < 0) retval = 16384;
	return retval;
}

/* PORT is a uint64_t. A port stores two file descriptors.
	 There are several cases:
	 HI     LO
	 ctl_fd ctl_fd -> ctl_fd, the stream socket waiting to accept a new connection
	 ctl_fd connfd -> (connfd != ctl_fd) accepted connection, waiting for a struct request
	 datafd connfd -> (connfd != datafd != ctl_fd) established connection (ctl socket.
	                  no data should be received on this socket. just EOF to close).
   datafd datafd -> (datafd != ctl_fd) data socket.
	 */

#define dualint(hi, lo) (((uint64_t)(hi) << 32) | (lo))
#define dualgetlo(x) ((uint32_t) x)
#define dualgethi(x) ((uint32_t) (x >> 32))

/* COMMON function to open a netnode */
static VDECONN *vde_netnode_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args, enum netnode_type nettype)
{
	char *path = vde_url;
	char userpath[PATH_MAX];
	struct vde_netnode_conn *newconn;
	int  epfd;
	int ctl_fd;
	struct epoll_event event = {.events = EPOLLIN};
	char *modestr = NULL;
	char *dirmodestr = NULL;
	char *grpstr = NULL;
	char *hashsizestr = NULL;
	char *hashseedstr = NULL;
	char *expiretimestr = NULL;
	struct vdeparms parms[] = {
		{"mode", &modestr},
		{"dirmode", &dirmodestr},
		{"grp", &grpstr},
		{"hashsize", &hashsizestr},
		{"hashseed", &hashseedstr},
		{"expiretime", &expiretimestr},
		{NULL, NULL}};
	int mode = STDMODE;
	int dirmode = STDDIRMODE;
	gid_t gid = -1;

	if (vde_parsepathparms(vde_url, parms) != 0)
		return NULL;

	/* if path==0, the standard path is /tmp/vdenode_${USERNAME} 
		 or /tmp/vdenode_u${EUID} if the euid is not in /etc/passwd.
		 e.g. /tmp/vdenode_renzo or /tmp/vdenode_u1000 */
	if (*path == 0) { 
		size_t bufsize = sysconf_getpw_r_size_max();
		char buf[bufsize];
		struct passwd pwd;
		struct passwd *result;
		uid_t euid = geteuid();
		getpwuid_r(euid, &pwd, buf, bufsize, &result);
		if (result)
			snprintf(userpath, PATH_MAX, STDPATH "%s", pwd.pw_name);
		else
			snprintf(userpath, PATH_MAX, STDPATH "u%d", euid);
		userpath[PATH_MAX-1] = 0;
		path = userpath;
	} else {
		char *filename=basename(path);
		char *dir=dirname(path);
		if ((path = realpath(dir, userpath)) == NULL)
			return NULL;
		strncat(path, "/", PATH_MAX);
		strncat(path, filename, PATH_MAX);
	}

	if (grpstr != NULL) {
		size_t bufsize = sysconf_getgr_r_size_max();
		char buf[bufsize];
		struct group grp;
		struct group *result;
		getgrnam_r(grpstr, &grp, buf, bufsize, &result);
		if (result)
			gid = grp.gr_gid;
		else if (isdigit(*grpstr))
			gid = strtol(grpstr, NULL, 0);
	}

	/* management of mode and dirmode. */
	if (modestr) mode = strtol(modestr, NULL, 8) & ~0111;
	if (dirmodestr) 
		dirmode = strtol(dirmodestr, NULL, 8);
	else if (modestr)
		dirmode = 02000 | mode | (mode & 0444) >> 2 | (mode & 0222) >> 1;

	/* epoll (a vdeplug has one fddata, so an epoll file descriptor can
		 can summarize the events coming from many fd) */
	if ((epfd = epoll_create1(EPOLL_CLOEXEC)) < 0)
		goto abort;
	if ((ctl_fd = datasock_open(path, gid, mode, dirmode)) < 0)
		goto abort_epoll;

	event.data.u64 = dualint(ctl_fd, ctl_fd);
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, ctl_fd, &event) < 0)
		goto abort_datasock;
	if ((newconn=calloc(1,sizeof(struct vde_netnode_conn)))==NULL) {
		errno=ENOMEM;
		goto abort_datasock;
	}
	newconn->nettype=nettype;
	newconn->epfd=epfd;
	newconn->ctl_fd=ctl_fd;
	newconn->mode=mode;
	newconn->path=strdup(path);
	newconn->porttab=NULL;
	newconn->porttablen=newconn->porttabmax=0;
	newconn->expiretime = expiretimestr ? atoi(expiretimestr) : STDEXPIRETIME;
	newconn->lastbonding = 0;
	if (nettype == SWITCHNODE) 
		newconn->hashtable = vde_hash_init(int, 
				hashsizestr ? atoi(hashsizestr) : STDHASHSIZE,
				hashseedstr ? atoi(hashseedstr) : 0);
	else
		newconn->hashtable = NULL;
	return (VDECONN *)newconn;
abort_datasock:
	close(ctl_fd);
	datasock_close(path);
abort_epoll:
	close(epfd);
abort:
	return NULL;
}

static VDECONN *vde_hub_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args) {
	return vde_netnode_open(vde_url, descr, interface_version, open_args, HUBNODE);
}

static VDECONN *vde_multi_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args) {
	return vde_netnode_open(vde_url, descr, interface_version, open_args, MULTINODE);
}

static VDECONN *vde_switch_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args) {
	return vde_netnode_open(vde_url, descr, interface_version, open_args, SWITCHNODE);
}

static VDECONN *vde_bonding_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args) {
	return vde_netnode_open(vde_url, descr, interface_version, open_args, BONDINGNODE);
}

/* get the vlan id from an Ethernet packet */
static inline int eth_vlan(const void *buf,size_t len) {
	if (__builtin_expect(len >= sizeof(struct ether_header) + 4, 1)) {
		struct ether_header *ethh = (void *) buf;
		uint16_t *vlanhdr = (void *) (ethh + 1);
		if (ntohs(ethh->ether_type) == ETHERTYPE_VLAN) 
			return  ntohs(*vlanhdr) & 0x3ff;
	}
	return 0;
}

/* get the source MAC from an Ethernet packet */
static inline uint8_t *eth_shost(const void *buf, size_t len) {
	struct ether_header *ethh = (void *) buf;
	return ethh->ether_shost;
}

/* get the destination MAC from an Ethernet packet */
static inline uint8_t *eth_dhost(const void *buf, size_t len) {
	struct ether_header *ethh = (void *) buf;
	return ethh->ether_dhost;
}

/* receive a packet (from one of the connected node, i.e. there is a pending 
	 epoll event */
static ssize_t vde_netnode_recv(VDECONN *conn, void *buf, size_t len, int flags)
{
	struct epoll_event event;
	ssize_t retval = 1;
	struct vde_netnode_conn *vde_conn = (struct vde_netnode_conn *)conn;
	if (epoll_wait(vde_conn->epfd, &event, 1, -1) > 0) {
		int fd = dualgetlo(event.data.u64);
		int fd2 = dualgethi(event.data.u64);
		if (fd == fd2) {
			if (fd == vde_conn->ctl_fd) {
				/* CTL IN */
				int conn_fd = ctl_in(vde_conn->path, vde_conn->ctl_fd);
				if (conn_fd >= 0) {
					event.events = EPOLLIN;
					event.data.u64 = dualint(vde_conn->ctl_fd, conn_fd);
					epoll_ctl(vde_conn->epfd, EPOLL_CTL_ADD, conn_fd, &event);
				}
			} else {
				/* DATA IN */
				len = read(fd, buf, len);
				if (__builtin_expect(len >= sizeof(struct ether_header), 1)) {
					if (vde_conn->nettype == MULTINODE || vde_conn->nettype == BONDINGNODE) 
						/* MULTINODE or BONDINGNODE -> to the host only */
						retval = len;
					else {
						int i;
						int *outfdp;
						time_t now = time(NULL);
						if (vde_conn->hashtable) 
							vde_find_in_hash_update(vde_conn->hashtable, eth_shost(buf, len), eth_vlan(buf, len), &fd, now);
						if (vde_conn->hashtable && 
								(outfdp = vde_find_in_hash(vde_conn->hashtable, eth_dhost(buf, len), eth_vlan(buf, len), now - vde_conn->expiretime)) != NULL) {
							if (*outfdp == HOSTFAKEFD)
								retval = len; /* to the host */
							else if (*outfdp != fd) /* avoid back delivery to the sender */
								write(*outfdp, buf, len);
						} else {
							/* HUB or BUM (broadcast, unknown receipient, multicast) */
							for (i = 0; i < vde_conn->porttablen; i++) {
								int outfd = dualgethi(vde_conn->porttab[i]);
								if (outfd != fd)
									write(outfd, buf, len);
							}
							retval = len;
						}
					}
				}
			}
		} else {
			if (fd2 == vde_conn->ctl_fd) {
				/* CONN_IN */
				int data_fd = conn_in(vde_conn->path, fd, vde_conn->mode);
				if (data_fd >= 0) {
					event.events = EPOLLIN;
					event.data.u64 = dualint(data_fd, fd);
					porttab_add(vde_conn, event.data.u64);
					epoll_ctl(vde_conn->epfd, EPOLL_CTL_MOD, fd, &event);
					event.data.u64 = dualint(data_fd, data_fd);
					epoll_ctl(vde_conn->epfd, EPOLL_CTL_ADD, data_fd, &event);
				}
			} else {
				/* close connection, EOF on the control socket */
				struct sockaddr_un sun;
				if (vde_conn->hashtable)
					vde_hash_delete(vde_conn->hashtable, &fd2);

				porttab_del(vde_conn, event.data.u64);
				epoll_ctl(vde_conn->epfd, EPOLL_CTL_DEL, fd, NULL);
				epoll_ctl(vde_conn->epfd, EPOLL_CTL_DEL, fd2, NULL);
				close(fd);
				close(fd2);
				sun.sun_family = AF_UNIX;
				snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/fd%d",vde_conn->path,fd);
				unlink(sun.sun_path);
			}
		}
	}
	return retval;
}

/* There is an avent coming from the host */
static ssize_t vde_netnode_send(VDECONN *conn, const void *buf, size_t len, int flags)
{
	if (__builtin_expect(len >= sizeof(struct ether_header), 1)) {
		int i;
		struct vde_netnode_conn *vde_conn = (struct vde_netnode_conn *)conn;
		int *outfdp;
		int infd = HOSTFAKEFD;
		time_t now = time(NULL);
		if (vde_conn->hashtable)
			vde_find_in_hash_update(vde_conn->hashtable, eth_shost(buf, len), eth_vlan(buf, len), &infd, now);
		if (vde_conn->hashtable && 
				(outfdp = vde_find_in_hash(vde_conn->hashtable, eth_dhost(buf, len), eth_vlan(buf, len), now - vde_conn->expiretime)) != NULL) {
			if (*outfdp != HOSTFAKEFD) /* avoid back delivery to the host */
				write(*outfdp, buf, len);
		} else {
			if (vde_conn->nettype == BONDINGNODE) {
				/* bonding: roung robind send packets on one available connection */
				if (vde_conn->porttablen > 0) {
					int outfd;
					vde_conn->lastbonding = (vde_conn->lastbonding + 1) % vde_conn->porttablen;
					outfd = dualgethi(vde_conn->porttab[vde_conn->lastbonding]);
					write(outfd, buf, len);
				}
			} else {
				/* HUB, MULTI or BUM (broadcast, unknown receipient, multicast) */
				for (i = 0; i < vde_conn->porttablen; i++) {
					int outfd = dualgethi(vde_conn->porttab[i]);
					write(outfd, buf, len);
				}
			}
		}
	}
	return len;
}

static int vde_netnode_datafd(VDECONN *conn)
{
	struct vde_netnode_conn *vde_conn = (struct vde_netnode_conn *)conn;
	return vde_conn->epfd;
}

static int vde_netnode_ctlfd(VDECONN *conn)
{
	return -1;
}

static int vde_netnode_close(VDECONN *conn)
{
	int i;
	struct vde_netnode_conn *vde_conn = (struct vde_netnode_conn *)conn;
	for (i = 0; i < vde_conn->porttablen; i++) {
		int fd = dualgetlo(vde_conn->porttab[i]);
		int fd2 = dualgethi(vde_conn->porttab[i]);
		struct sockaddr_un sun;
		close(fd);
		close(fd2);
		sun.sun_family = AF_UNIX;
		snprintf(sun.sun_path,sizeof(sun.sun_path), "%s/fd%d", vde_conn->path,fd);
		unlink(sun.sun_path);
	}
	datasock_close(vde_conn->path);
	close(vde_conn->ctl_fd);
	close(vde_conn->epfd);
	if (vde_conn->porttab)
		free(vde_conn->porttab);
	if (vde_conn->hashtable)
		vde_hash_fini(vde_conn->hashtable);
	free(vde_conn->path);
	free(vde_conn);
	return 0;
}
