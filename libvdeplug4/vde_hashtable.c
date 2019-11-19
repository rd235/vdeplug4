#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <libvdeplug_mod.h>

struct vde_hashtable {
	size_t payload_size;
	unsigned int hash_mask;
	uint64_t seed;
	/* plus the table here */
	char ht[];
};

struct ht_elem {
	uint64_t edst;
	time_t last_seen;
	char payload[];
};
#define sizeof_ht_elem(payload_size) (sizeof(struct ht_elem) + payload_size)

static inline __attribute__((always_inline)) struct ht_elem *ht_get(struct vde_hashtable *table, int index) {
	return (void *) (table->ht + index * sizeof_ht_elem(table->payload_size));
}

static inline __attribute__((always_inline)) int calc_hash(uint64_t src, unsigned int hash_mask, uint64_t seed)
{
	src ^= src >> 33 ^ seed; 
	src *= 0xff51afd7ed558ccd; 
	src ^= src >> 33;
	src *= 0xc4ceb9fe1a85ec53; 
	src ^= src >> 33;
	return src & hash_mask;
}

#define extmac(MAC,VLAN) \
	((*(uint32_t *) &((MAC)[0])) + ((uint64_t) ((*(uint16_t *) &((MAC)[4]))+ ((uint64_t) (VLAN) << 16)) << 32))


/* look in global hash table for given address, and return associated address */
void *vde_find_in_hash(struct vde_hashtable *table, unsigned char *dst, int vlan, time_t too_old)
{
	if (__builtin_expect(table == NULL, 0))
		return NULL;
	else {
		uint64_t edst;
		int index;
		struct ht_elem *entry;

		if ((dst[0] & 1) == 1) /* broadcast */
			return NULL;
		edst = extmac(dst,vlan);
		index = calc_hash(edst, table->hash_mask, table->seed);
		//printf("index %d\n",index);
		entry = ht_get(table, index);
		if (entry->edst == edst && entry->last_seen >= too_old)
			return &(entry->payload);
		else
			return NULL;
	}
}

void vde_find_in_hash_update(struct vde_hashtable *table, unsigned char *src, int vlan, void *payload, time_t now)
{
	if (__builtin_expect(table == NULL, 0))
		return;
	else {
		uint64_t esrc;
		int index;
		struct ht_elem *entry;

		if ((src[0] & 1) == 1) /* broadcast */
			return;

		esrc = extmac(src,vlan);
		index = calc_hash(esrc, table->hash_mask, table->seed);
		//printf("index %d\n",index);

		entry = ht_get(table, index);
		entry->edst = esrc;
		memcpy(&(entry->payload),payload,table->payload_size);
		entry->last_seen = now;
	}
}

void vde_hash_delete(struct vde_hashtable *table, void *payload)
{
	if (__builtin_expect(table == NULL, 0))
		return;
	else {
		unsigned int i;
		for (i = 0; i < table->hash_mask + 1; i++) {
			struct ht_elem *entry =  ht_get(table, i);
			if (memcmp(entry->payload, payload, table->payload_size) == 0)
				entry->last_seen = 0;
		}
	}
}

// #define vde_hash_init(type, hash_mask, seed) _vde_hash_init(sizeof(type), (hash_mask), (seed))

struct vde_hashtable *_vde_hash_init(size_t payload_size, unsigned int hashsize, uint64_t seed)
{
	struct vde_hashtable *retval;
	if (hashsize == 0)
		return NULL;
	hashsize = (2 << (sizeof(hashsize) * 8 - __builtin_clz(hashsize - 1) - 1));

	retval = calloc(1, sizeof(struct vde_hashtable) 
			+ hashsize * sizeof_ht_elem(payload_size));
	if (retval) {
		retval->payload_size = payload_size;
		retval->hash_mask = hashsize - 1;
		retval->seed = seed;
	}
	return retval;
}

void vde_hash_fini(struct vde_hashtable *table)
{
	free(table);
}

#if 0
int main() {
	struct vde_hashtable *ht = vde_hash_init(int, 15, 0);

	while(1) {
		unsigned char mac[7];
		unsigned int port;
		scanf("%6s %u",mac,&port);
		printf("%s %d \n",mac,port);
		if (port == 0) {
			int *pport = vde_find_in_hash(ht, mac, 0, time(NULL)-20);
			if (pport)
				printf("-> %d\n", *pport);
			else
				printf("-> not found\n");
		} else
			vde_find_in_hash_update(ht, mac, 0, &port, time(NULL));
	}
}
#endif
