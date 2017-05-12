/*
 * VDE - libvdeplug_vx modules 
 * Copyright (C) 2014-2016 Renzo Davoli VirtualSquare
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include "libvdeplug_mod.h"

#define DEFADDRV4 "239.0.0.1"
#define DEFADDRV6 "ff05:56de::1"
#define STDPORTSTR "4789"
#define STDTTLSTR "1"
#define STDVNISTR "1"
#define STDHASHSIZE 1024
#define STDEXPIRETIME 128

#define ETH_ALEN 6
#define ETH_HEADER_SIZE 14
#define IS_BROADCAST(addr) ((addr[0] & 1) == 1)

#define ntoh24(p) (((p)[0] << 16) | ((p)[1] << 8) | ((p)[2]))
#define hton24(p, v) { \
	p[0] = (((v) >> 16) & 0xFF); \
	p[1] = (((v) >> 8) & 0xFF); \
	p[2] = ((v) & 0xFF); \
}

struct eth_hdr {
	unsigned char dest[ETH_ALEN];
	unsigned char src[ETH_ALEN];
	unsigned char proto[2];
};

struct vxlan_hdr {
	unsigned char flags;
	unsigned char priv1[3];
	unsigned char id[3];
	unsigned char priv2[1];
};

static VDECONN *vde_vxlan_open(char *given_vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_vxlan_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_vxlan_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_vxlan_datafd(VDECONN *conn);
static int vde_vxlan_ctlfd(VDECONN *conn);
static int vde_vxlan_close(VDECONN *conn);

union sockaddr46 {
	struct sockaddr vx;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

struct vde_vxlan_conn {
	void *handle;
	struct vdeplug_module *module;
	struct vde_hashtable *table;
	int vni;
	union sockaddr46 multiaddr;
	in_port_t multiport;
	int multifd;
	int expiretime;
};

struct vdeplug_module vdeplug_ops={
	.vde_open_real=vde_vxlan_open,
	.vde_recv=vde_vxlan_recv,
	.vde_send=vde_vxlan_send,
	.vde_datafd=vde_vxlan_datafd,
	.vde_ctlfd=vde_vxlan_ctlfd,
	.vde_close=vde_vxlan_close
};

static inline socklen_t fam2socklen(void *sockaddr)
{
	struct sockaddr *s=sockaddr;
	switch (s->sa_family) {
		case AF_INET: return sizeof(struct sockaddr_in);
		case AF_INET6: return sizeof(struct sockaddr_in6);
		default: return 0;
	}
}

static inline void setport(void *sockaddr, in_port_t port)
{
	struct sockaddr *s=sockaddr;
	switch (s->sa_family) {
		case AF_INET: ((struct sockaddr_in *) s)->sin_port = port;
									return;
		case AF_INET6: ((struct sockaddr_in6 *) s)->sin6_port = port;
									 return;
	}
}

static VDECONN *vde_vxlan_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	struct vde_vxlan_conn *newconn;
	struct addrinfo hints;
	struct addrinfo *result,*rp;
	int s;
	unsigned int hashsize = STDHASHSIZE;
	char *portstr = STDPORTSTR;
	char *vnistr = STDVNISTR;
	char *ttlstr = STDTTLSTR;
	char *rcvbufstr = NULL;
	char *v6str = NULL;
	char *v4str = NULL;
	char *hashsizestr = NULL;
	char *expiretimestr = NULL;
	char *ifstr = NULL;
	struct vdeparms parms[] = {
		{"port",&portstr},
		{"vni",&vnistr},
		{"ttl",&ttlstr},
		{"rcvbuf",&rcvbufstr},
		{"v6",&v6str},
		{"v4",&v4str},
		{"hashsize",&hashsizestr},
		{"expiretime",&expiretimestr},
		{"if",&ifstr},
		{NULL, NULL}};
	struct sockaddr *multiaddr=NULL;
	int multifd=-1;
	int ttl;
	in_port_t multiport;
	unsigned int ifindex = 0;

	memset(&hints, 0, sizeof(struct addrinfo));
	/* Allow IPv4 or IPv6 if either none or both options v4/v6 were selected*/
	switch (((!!v6str) << 1) | (!!v4str)) {
		case 0: hints.ai_family = AF_UNSPEC; break;
		case 1: hints.ai_family = AF_INET; break;
		case 2: hints.ai_family = AF_INET6; break;
		case 3: hints.ai_family = AF_UNSPEC; break;
	}
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_protocol = 0;          /* Any protocol */
	if (vde_parseparms(vde_url, parms) != 0)
		return NULL;
	ttl = atoi(ttlstr);

	if (*vde_url == 0)
		vde_url = v6str != NULL ? DEFADDRV6 : DEFADDRV4;
	if (ifstr != NULL)
		ifindex = if_nametoindex(ifstr);

	s = getaddrinfo(vde_url, portstr, &hints, &result);
	if (s < 0) {
		fprintf(stderr, "vxlan getaddrinfo: %s\n", gai_strerror(s));
		errno=ENOENT;
		return NULL;
	}

	for (rp = result; rp != NULL && multifd < 0; rp = rp->ai_next) {
		switch (rp->ai_family) {
			case AF_INET6: {
											 struct sockaddr_in6 *addr=(struct sockaddr_in6 *)(rp->ai_addr);
											 struct ipv6_mreq mc_req;
											 multiaddr = (struct sockaddr *) addr;
											 struct sockaddr_in6 bindaddr;
											 int loop = 0;

											 if ((multifd=socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP)) < 0)
												 goto error;
											 if (rcvbufstr) {
												 unsigned int rcvbuf = strtoullm(rcvbufstr);
												 if ((setsockopt(multifd, SOL_SOCKET, SO_RCVBUF,
																 &rcvbuf, sizeof(rcvbuf))) < 0)
													 goto error;
											 }
											 if ((setsockopt(multifd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
															 &ttl, sizeof(ttl))) < 0)
												 goto error;
											 if ((setsockopt(multifd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
															 &loop, sizeof(loop))) < 0)
												 goto error;

											 /* bind to in6addr_any to receive both unicast and multicast */
											 memset(&bindaddr, 0, sizeof(bindaddr));
											 bindaddr.sin6_family      = AF_INET6;
											 memcpy(&bindaddr.sin6_addr, &in6addr_any, sizeof(in6addr_any));
											 bindaddr.sin6_port        = multiport = addr->sin6_port;
											 if ((bind(multifd, (struct sockaddr *) &bindaddr,
															 sizeof(bindaddr))) < 0) {
												 close(multifd);
												 multifd=-1;
												 continue;
											 }

											 memcpy(&mc_req.ipv6mr_multiaddr, &addr->sin6_addr,
													 sizeof(addr->sin6_addr));
											 mc_req.ipv6mr_interface = ifindex;
											 if ((setsockopt(multifd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
															 &mc_req, sizeof(mc_req))) < 0)
												 goto error;
											 if (ifindex > 0) {
												 if ((setsockopt(multifd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex,
																 sizeof(ifindex))) < 0)
													 goto error;
											 }
											 break;
										 }
			case AF_INET: {
											struct sockaddr_in *addr=(struct sockaddr_in *)(rp->ai_addr);
											struct ip_mreqn mc_req;
											multiaddr = (struct sockaddr *) addr;
											struct sockaddr_in bindaddr;
											int loop = 0;

											if ((multifd=socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP)) < 0)
												goto error;
											if (rcvbufstr) {
												unsigned int rcvbuf = strtoullm(rcvbufstr);
												if ((setsockopt(multifd, SOL_SOCKET, SO_RCVBUF,
																&rcvbuf, sizeof(rcvbuf))) < 0)
													goto error;
											}
											if ((setsockopt(multifd, IPPROTO_IP, IP_MULTICAST_TTL,
															&ttl, sizeof(ttl))) < 0) 
												goto error;
											if ((setsockopt(multifd, IPPROTO_IP, IP_MULTICAST_LOOP,
															&loop, sizeof(loop))) < 0) 
												goto error;

											memset(&bindaddr, 0, sizeof(bindaddr));
											bindaddr.sin_family      = AF_INET;
											bindaddr.sin_addr.s_addr = htonl(INADDR_ANY);
											bindaddr.sin_port        = multiport = addr->sin_port;
											if ((bind(multifd, (struct sockaddr *) &bindaddr,
															sizeof(bindaddr))) < 0) {
												close(multifd);
												multifd=-1;
												continue;
											}

											mc_req.imr_multiaddr.s_addr = addr->sin_addr.s_addr;
											mc_req.imr_address.s_addr = htonl(INADDR_ANY);
											mc_req.imr_ifindex = ifindex;
											if ((setsockopt(multifd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
															&mc_req, sizeof(mc_req))) < 0) 
												goto error;

											if (ifindex > 0) {
												mc_req.imr_multiaddr.s_addr = htonl(INADDR_ANY);
												mc_req.imr_address.s_addr = htonl(INADDR_ANY);
												mc_req.imr_ifindex = ifindex;
												if ((setsockopt(multifd, IPPROTO_IP, IP_MULTICAST_IF, &mc_req,
																sizeof(mc_req))) < 0)
													goto error;
											}
											break;
										}
		}
	}

	if (multifd < 0) {
		errno = ENETUNREACH;
		goto error;
	}

	if ((newconn=calloc(1,sizeof(struct vde_vxlan_conn)))==NULL)
	{
		errno = ENOMEM;
		goto error;
	}

	if (hashsizestr != NULL) 
		hashsize = atoi(hashsizestr);
	switch (multiaddr->sa_family) {
		case AF_INET6:
			newconn->table = vde_hash_init(struct sockaddr_in6 , hashsize, 0);
			break;
		case AF_INET:
			newconn->table = vde_hash_init(struct sockaddr_in , hashsize, 0);
			break;
		default:
			newconn->table = NULL;
			break;
	}
	newconn->vni=atoi(vnistr);
	if (expiretimestr != NULL) {
		newconn->expiretime = atoi(expiretimestr);
		if (newconn->expiretime <= 0)
			newconn->expiretime = STDEXPIRETIME;
	} else
		newconn->expiretime = STDEXPIRETIME;
	memcpy(&(newconn->multiaddr.vx), multiaddr, fam2socklen(multiaddr));
	newconn->multiport = multiport;
	newconn->multifd = multifd;
	freeaddrinfo(result);
	return (VDECONN *) newconn;

error:
	freeaddrinfo(result);
	if (multifd >= 0) close(multifd);
	if (newconn != NULL) free(newconn);
	return NULL;
}

static ssize_t vde_vxlan_recv(VDECONN *conn,void *buf,size_t len,int flags) {
	struct vde_vxlan_conn *vde_conn = (struct vde_vxlan_conn *)conn;
	struct vxlan_hdr vhdr;
	struct iovec iov[]={{&vhdr, sizeof(vhdr)},{buf, len}};
	struct msghdr msg;
	struct sockaddr_in6 sender;
	ssize_t retval;
	msg.msg_name=&sender;
	msg.msg_namelen = fam2socklen(msg.msg_name);
	msg.msg_iov=iov;
	msg.msg_iovlen=2;
	msg.msg_control=NULL;
	msg.msg_controllen=0;
	msg.msg_flags=0;
	retval=recvmsg(vde_conn->multifd, &msg, 0)-sizeof(struct vxlan_hdr);
	if (__builtin_expect((retval > ETH_HEADER_SIZE), 1)) {
		struct eth_hdr *ehdr=(struct eth_hdr *) buf;
		if (vhdr.flags != (1 << 3) || ntoh24(vhdr.id) != vde_conn->vni)
			goto error;
		/* VXLAN always sends packets to the multicast port */
		setport(msg.msg_name, vde_conn->multiport);
		vde_find_in_hash_update(vde_conn->table, ehdr->src, 1, msg.msg_name, time(NULL));
		return retval;
	}
error:
	errno = EAGAIN;
	*((unsigned char *)buf)=0;
	return 1;
}

static ssize_t vde_vxlan_send(VDECONN *conn,const void *buf, size_t len,int flags) {
	struct vde_vxlan_conn *vde_conn = (struct vde_vxlan_conn *)conn;
	struct vxlan_hdr vhdr;
	struct iovec iov[]={{&vhdr, sizeof(vhdr)},{(char *)buf, len}};
	struct sockaddr *destaddr;
	static struct msghdr msg;
	ssize_t retval;
	msg.msg_iov=iov;
	msg.msg_iovlen=2;
	struct eth_hdr *ehdr=(struct eth_hdr *) buf;
	if (len < ETH_HEADER_SIZE)
		return len; // discard packets shorter than an ethernet header
	if (IS_BROADCAST(ehdr->dest) || 
			(destaddr = vde_find_in_hash(vde_conn->table, ehdr->dest, 1, time(NULL)- vde_conn->expiretime)) == NULL)
		/* MULTICAST */
		msg.msg_name = &(vde_conn->multiaddr.vx);
	else
		/* UNICAST */
		msg.msg_name = destaddr;
	msg.msg_namelen = fam2socklen(msg.msg_name);
	memset(&vhdr, 0, sizeof(vhdr));
	vhdr.flags = (1 << 3);

	hton24(vhdr.id, vde_conn->vni);

	if ((retval=sendmsg(vde_conn->multifd, &msg, 0)) < 0)
		return -1;
	retval -= sizeof(struct vxlan_hdr);
	if (retval < 0)
		retval = 0;
	return retval;
}

static int vde_vxlan_datafd(VDECONN *conn) {
	struct vde_vxlan_conn *vde_conn = (struct vde_vxlan_conn *)conn;
	return vde_conn->multifd;
}

static int vde_vxlan_ctlfd(VDECONN *conn) {
	return -1;
}

static int vde_vxlan_close(VDECONN *conn) {
	struct vde_vxlan_conn *vde_conn = (struct vde_vxlan_conn *)conn;
	close(vde_conn->multifd);
	vde_hash_fini(vde_conn->table);
	free(vde_conn);
	return 0;
}
