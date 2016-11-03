/* 
 * Copyright (C) 2016  Renzo Davoli, University of Bologna
 * 
 * parse parameters for vdeplug modules.
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

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <grp.h>
#include <sys/types.h>

#include <libvdeplug.h>
#include <libvdeplug_mod.h>

#if 0
// defined in libvdeplug_mod.h. 
struct vdeparms {
	char *tag;
	char **value;
};
#endif
static inline int isnumber(const char *s) {
	while (1) {
		if (!isdigit(*s++)) return 0; /* an empty string is *not* a number */
		if (*s == 0) return 1;
	}
}

unsigned long long strtoullm(const char *numstr) {
	char *tail;
	unsigned long long rval = strtoull(numstr, &tail, 0);
	for (; *tail; tail++) {
		switch (*tail) {
			case 'k':
			case 'K': rval *= 1ULL<<10; break;
			case 'm':
			case 'M': rval *= 1ULL<<20; break;
			case 'g':
			case 'G': rval *= 1ULL<<30; break;
			case 't':
			case 'T': rval *= 1ULL<<40; break;
		}
	}
	return rval;
}

gid_t vde_grnam2gid(const char *name) {
	if (name) {
		if (*name == 0)
			return getegid();
		else if (isnumber(name))
			return atoi(name);
		else {
			struct group grp;
			struct group *rgrp;
			size_t buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
			char buf[buflen];
			getgrnam_r(name, &grp, buf, buflen, &rgrp);
			return rgrp ? grp.gr_gid : -1;
		}
	}
	return -1;
}

#define CHAR 0
#define QUOTE 1
#define DOUBLEQ 2
#define ESC 3
#define DELIM 4
#define END 5

#define COPY 1

static char nextstate[4][6] = {
	{CHAR, QUOTE, DOUBLEQ, ESC, DELIM, END},
	{QUOTE, CHAR, QUOTE, QUOTE, QUOTE, END},
	{DOUBLEQ, DOUBLEQ, CHAR, DOUBLEQ, DOUBLEQ, END},
	{CHAR, CHAR, CHAR, CHAR, CHAR, END}};

static char action[4][6] = {
	{COPY, 0, 0, 0, 0, 0},
	{COPY, 0, COPY, COPY, COPY, 0},
	{COPY, COPY, 0, COPY, COPY, 0},
	{COPY, COPY, COPY, COPY, COPY, 0}};


static char *strtokq_r(char *s, const char *delim, char **saveptr) {
	char *begin, *from, *to;
	int status = CHAR;
	begin = (s == NULL) ? *saveptr : s;
	from = to = begin;
	if (from == NULL)
		return NULL;
	begin = from;
	while ((status & DELIM) == 0) { /* this includes END */
		int this;
		int todo;
		switch (*from) {
			case 0: this = END; break;
			case '\'': this = QUOTE; break;
			case '\"': this = DOUBLEQ; break;
			case '\\': this = ESC; break;
			default: this = strchr(delim, *from) == NULL ? CHAR : DELIM;
		}
		todo = action[status][this];
		if (todo & COPY)
			*to++ = *from++;
		else
			from++;
		status = nextstate[status][this];
	}
	*to = 0;
	*saveptr = (status == END) ? NULL : from;
	return begin;
}


int vde_parseparms(char *str,struct vdeparms *parms){
	if (*str != 0) {
		str = strchr(str,'/');
		if (str) {
			char *sp;
			char *elem;
			do
				*(str++)=0;
			while (*str == '/');
			for (; (elem = strtokq_r(str,"/",&sp)) != NULL ; str = NULL) {
				char *eq = strchr(elem, '=');
				int taglen=eq ? eq-elem : strlen(elem);
				struct vdeparms *scan;
				for (scan = parms; scan->tag; scan++) {
					if (strncmp(elem,scan->tag,taglen) == 0) {
						*(scan->value)=eq ? eq+1 : "";
						break;
					}
				}
				if (scan->tag == NULL) {
					fprintf(stderr,"unknwown key: %*.*s\n",taglen,taglen,elem);
					errno = EINVAL;
					return -1;
				}
			}
		}
	}
	return 0;
}


#if 0
int main(int argc, char *argv[]) {
	char *portstr="12345";
	char *vnistr="1";
	char *ttlstr="1";
	struct parms parms[] = {{"port",&portstr},{"vni",&vnistr},{"ttl",&ttlstr},{NULL, NULL}};

	parseparms(argv[1],parms);

	struct parms *scan;
	for (scan = parms; scan->tag; scan++)
		printf("%s %s\n",scan->tag,*(scan->value));
}
#endif
