/*
 * VDE - libvdeplug_vx modules 
 * Copyright (C) 2014 Renzo Davoli VirtualSquare
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

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include "libvdeplug_vxhash.h"

struct hash_entry6 {
	u_int64_t edst;
	time_t last_seen;
	struct sockaddr_in6 addr;
};

struct hash_entry4 {
	u_int64_t edst;
	time_t last_seen;
	struct sockaddr_in addr;
};

struct hash_entry {
	u_int64_t edst;
	time_t last_seen;
	struct sockaddr addr;
};

static int calc_hash(u_int64_t src, unsigned int hash_mask)
{
	/* proposal: add this to reduce the probability
	that collisions survive a hash table size change */
	/* src ^= hash_mask; */
	src ^= src >> 33;
	src *= 0xff51afd7ed558ccd;
	src ^= src >> 33;
	src *= 0xc4ceb9fe1a85ec53;
	src ^= src >> 33;
	return src & hash_mask;
}

#define extmac(MAC,VLAN) \
	        ((*(u_int32_t *) &((MAC)[0])) + ((u_int64_t) ((*(u_int16_t *) &((MAC)[4]))+ ((u_int64_t) (VLAN) << 16)) << 32))

/* look in global hash table for given address, and return associated sockaddr */
struct sockaddr *vx_find_in_hash(void *table, int sa_family, unsigned int hash_mask,
		unsigned char *dst, int vlan, time_t too_old)
{
	u_int64_t edst;
	int index;
	struct hash_entry *entry;

	if (__builtin_expect(table == NULL, 0))
		return NULL;
	if ((dst[0] & 1) == 1) /* broadcast */
		return NULL;
	edst=extmac(dst,vlan);
	index=calc_hash(edst, hash_mask);
	switch (sa_family) {
		case AF_INET: entry = (struct hash_entry *)((struct hash_entry4 *)table)+index;
						break;
		case AF_INET6: entry = (struct hash_entry *)((struct hash_entry6 *)table)+index;
						break;
		default:
						return NULL;
	}
	if (entry->edst == edst && entry->last_seen >= too_old)
		return &(entry->addr);
	else
		return NULL;
}

void vx_find_in_hash_update(void *table, unsigned int hash_mask,
		unsigned char *src, int vlan, struct sockaddr *addr, time_t now)
{
	u_int64_t esrc;
	int index;
	size_t addrlen;
	struct hash_entry *entry;
	if (__builtin_expect(table == NULL, 0))
		return;
	if ((src[0] & 1) == 1) /* broadcast */
		return;
	esrc=extmac(src,vlan);
	index=calc_hash(esrc, hash_mask);

	switch (addr->sa_family) {
		case AF_INET: entry = (struct hash_entry *)((struct hash_entry4 *)table)+index;
						addrlen = sizeof(struct sockaddr_in);
						break;
		case AF_INET6: entry = (struct hash_entry *)((struct hash_entry6 *)table)+index;
						addrlen = sizeof(struct sockaddr_in6);
						break;
		default:
						return;
	}
	entry->edst=esrc;
	memcpy(&(entry->addr),addr,addrlen);
	entry->last_seen=now;
}

void vx_hash_delete(void *table, unsigned int hash_mask,
		 struct sockaddr *addr)
{
	unsigned int i;
	switch (addr->sa_family) {
		case AF_INET: { struct hash_entry4 *t4 = table;
										for (i = 0; i < hash_mask + 1; i++) {
											if (memcmp(&t4[i].addr, addr, sizeof(struct sockaddr_in)) == 0)
												t4[i].last_seen = 0;
										}
										break;
									}
		case AF_INET6: { struct hash_entry6 *t6 = table;
										 for (i = 0; i < hash_mask + 1; i++) {
											 if (memcmp(&t6[i].addr, addr, sizeof(struct sockaddr_in6)) == 0)
												 t6[i].last_seen = 0;
										 }
										 break;
									 }
	}
}

/* hash_mask must be 2^n - 1 */
void *vx_hash_init(int sa_family, unsigned int hash_mask)
{
	size_t elsize;
	switch (sa_family) {
		case AF_INET: elsize=sizeof(struct hash_entry4); break;
		case AF_INET6: elsize=sizeof(struct hash_entry6); break;
		default:
						return NULL;
	}

	return calloc(hash_mask+1, elsize);
}

void vx_hash_fini(void *table)
{
	if (table != NULL)
		free(table);
}
