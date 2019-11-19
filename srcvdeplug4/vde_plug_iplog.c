/* 
 * Copyright (C) 2002-2016  Renzo Davoli, University of Bologna
 * Modified by Ludovico Gardenghi 2005
 * 
 * iplog: log unique IP addresses seen on a line
 *
 * VDE is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>. 
 *
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <vde_plug_log.h>
#define ETH_ALEN 6

struct header {
	unsigned char dest[ETH_ALEN];
	unsigned char src[ETH_ALEN];
	unsigned char proto[2];
};

union body {
	struct {
		unsigned char version;
		unsigned char filler[11];
		unsigned char ip4src[4];
		unsigned char ip4dst[4];
	} v4;
	struct {
		unsigned char version;
		unsigned char filler[7];
		unsigned char ip6src[16];
		unsigned char ip6dst[16];
	} v6;
	struct {
		unsigned char priovlan[2];
	} vlan;
};

struct addrelem {
	struct addrelem *next;
	unsigned int len;
	char addr[];
};

static unsigned long hash(unsigned int len, unsigned char *addr)
{
	unsigned long hash = 5381;
	int i;
	for (i = 0; i < len; i++)
		hash = ((hash << 5) + hash) + addr[i];
	return hash;
}

static int search_n_add(struct addrelem **scan, unsigned int len, unsigned char *addr) {
	struct addrelem *new;
	for (; *scan != NULL ; scan = &((*scan)->next)) 
		if ((*scan)->len == len && memcmp((*scan)->addr,addr,len) == 0)
			return 0;
	new = malloc(sizeof(struct addrelem) + len);
	if (new) {
		new->next = NULL;
		new->len = len;
		memcpy(new->addr, addr, len);
		*scan = new;
		return 1;
	} 
	return -1;
}

#define HASH_MASK 511

void hash_add_n_run(unsigned int len, unsigned char *addr, void *arg,
		void (*f)(unsigned int len, unsigned char *addr, void *arg)) {
	static struct addrelem **htable;
	unsigned long hashkey;

	if (__builtin_expect(htable == NULL, 0)) 
		htable = calloc(HASH_MASK + 1, sizeof(struct addrelem *));

	hashkey = hash(len, addr) % HASH_MASK;

	if (search_n_add(&(htable[hashkey]), len, addr) == 1) 
		f(len, addr, arg);
}

void printlogv4(unsigned int len, unsigned char *addr, void *arg) {
	char straddr[256];
	int *pvlan = arg;
	syslog(LOG_INFO, "user %s Real-IP %s has got VDE-IP4 %s on vlan %d",
			username, sshremotehost, inet_ntop(AF_INET, addr, straddr, 256), *pvlan);

}

void printlogv6(unsigned int len, unsigned char *addr, void *arg) {
	char straddr[256];
	int *pvlan = arg;
	syslog(LOG_INFO, "user %s Real-IP %s has got VDE-IP6 %s on vlan %d",
			username, sshremotehost, inet_ntop(AF_INET6, addr, straddr, 256), *pvlan);

}

void vde_ip_check(const unsigned char *buf, int rnx) 
{
	struct header *ph = (struct header *) buf;
	int vlan = 0;
	union body *pb;

	pb = (union body *)(ph+1);
	if (ph->proto[0] == 0x81 && ph->proto[1] == 0x00) { /*VLAN*/
		vlan = ((pb->vlan.priovlan[0] << 8) + pb->vlan.priovlan[1]) & 0xfff;
		pb = (union body *)(((char *)pb)+4);
	}
	if (ph->proto[0] == 0x08 && ph->proto[1] == 0x00 && 
			pb->v4.version == 0x45) {
		/*v4 */ 
		hash_add_n_run(4, pb->v4.ip4src, &vlan, printlogv4);
	}
	else if (ph->proto[0] == 0x86 && ph->proto[1] == 0xdd && 
			pb->v4.version == 0x60) {
		/* v6 */
		hash_add_n_run(16, pb->v6.ip6src, &vlan, printlogv6);
	}
}
