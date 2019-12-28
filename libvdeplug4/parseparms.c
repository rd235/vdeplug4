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
#define PERC 4
#define PER2 5
#define DELIM 6
#define END 7
#define TSIZE (END + 1)

#define COPY 1
#define CPER 3

static char nextstate[TSIZE - 1][TSIZE] = {
	{CHAR,    QUOTE,   DOUBLEQ, ESC,     PERC,    0, DELIM,   END},
	{QUOTE,   CHAR,    QUOTE,   QUOTE,   QUOTE,   0, QUOTE,   END},
	{DOUBLEQ, DOUBLEQ, CHAR,    DOUBLEQ, DOUBLEQ, 0, DOUBLEQ, END},
	{CHAR,    CHAR,    CHAR,    CHAR,    CHAR,    0, CHAR,    END},
	{PER2,    QUOTE,   DOUBLEQ, ESC,     PERC,    0, DELIM,   END},
	{CHAR,    QUOTE,   DOUBLEQ, ESC,     PERC,    0, DELIM,   END},
	{CHAR,    QUOTE,   DOUBLEQ, ESC,     PERC,    0, DELIM,   END},
};

static char action[TSIZE - 2][TSIZE] = {
	{COPY, 0,    0,    0,    COPY, 0, 0,    0}, //char
	{COPY, 0,    COPY, COPY, COPY, 0, COPY, 0}, //quote
	{COPY, COPY, 0,    COPY, COPY, 0, COPY, 0}, //doubleq
	{COPY, COPY, COPY, COPY, COPY, 0, COPY, 0}, //esc
	{COPY, 0,    0,    0,    COPY, 0, 0,    0}, //perc
	{CPER, 0,    0,    0,    COPY, 0, 0,    0}, //per2
};

static const char *hexchars = "0123456789ABCDEF0123456789abcdef";
static inline int ch2n(char x) {
	char *n = strchr(hexchars, x);
	return n ? (n - hexchars) % 16 : -1;
}

static int token(char c, const char *delim) {
	int this;
	switch (c) {
		case 0: this = END; break;
		case '\'': this = QUOTE; break;
		case '\"': this = DOUBLEQ; break;
		case '\\': this = ESC; break;
		case '%': this = PERC; break;
		default: this = strchr(delim, c) == NULL ? CHAR : DELIM;
	}
	return this;
}

/* like strtok_r(3) + this function supports quoting with ' " and char protection \ */
static char *strtokq_r(char *s, const char *delim, char **saveptr) {
	char *begin, *from, *to;
	int status = CHAR;
	begin = from = to = (s == NULL) ? *saveptr : s;
	if (from == NULL)
		return NULL;
	while (status != DELIM && status != END) {
		int this = token(*from, delim);
		int todo = action[status][this];
		// printf("%c %d -> %d\n", *from, status, nextstate[status][this]);
		if (todo & COPY) {
			*to = *from;
			if (todo == CPER) {
				char *perc = to - 2;
				int hex1 = ch2n(perc[1]);
				int hex2 = ch2n(perc[2]);
				if (hex1 >= 0 && hex2 >= 0) {
					*perc = hex1 * 0x10 + hex2;
					to = perc;
				}
			}
			to++;
		}
		from++;
		status = nextstate[status][this];
	}
	*to = 0;
	*saveptr = (status == END) ? NULL : from;
	return begin;
}

static char *strtokq_nostrip_r(char *s, const char *delim, char **saveptr) {
	char *begin, *from, *to;
	int status = CHAR;
	begin = from = to = (s == NULL) ? *saveptr : s;
	if (from == NULL)
		return NULL;
	while (status != DELIM && status != END) {
		int this = token(*from, delim);
		if (this != DELIM) to++;
		from++;
		status = nextstate[status][this];
	}
	*to = 0;
	*saveptr = (status == END) ? NULL : from;
	return begin;
}

/* this function splits the token using the last (non quoted) occurence of the delimiter */
static char *strtokq_rev_r(char *s, const char *delim) {
	char *begin, *scan, *to;
	int status = CHAR;
	scan = begin = s;
	to = NULL;
	if (scan == NULL)
		return NULL;
	for (;status != END; scan++) {
		int this = token(*scan, delim);
		status = nextstate[status][this];
		if (status == DELIM) to = scan;
	}
	if (to != NULL) *to = 0;
	return begin;
}

int vde_parseparms(char *str, struct vdeparms *parms){
	if (*str != 0) {
		char *sp;
		char *elem;
		elem = strtokq_r(str, "/", &sp);
		while((elem = strtokq_r(NULL, "/", &sp)) != NULL) {
			char *eq = strchr(elem, '=');
			int taglen=eq ? eq-elem : strlen(elem);
			if (taglen > 0) {
				struct vdeparms *scan;
				for (scan = parms; scan->tag; scan++) {
					if (strncmp(elem, scan->tag, taglen) == 0) {
						*(scan->value)=eq ? eq+1 : "";
						break;
					}
				}
				if (scan->tag == NULL) {
					fprintf(stderr, "unknwown key: %*.*s\n", taglen, taglen, elem);
					errno = EINVAL;
					return -1;
				}
			}
		}
	}
	return 0;
}

int vde_parsepathparms(char *str, struct vdeparms *parms){
	if (*str != 0) {
		char *sp;
		char *elem;
		char *bracket;
		elem = strtokq_r(str, "[", &sp);
		for (bracket = strtokq_rev_r(sp, "]");
				(elem = strtokq_r(bracket, "/", &sp)) != NULL; bracket = NULL) {
			char *eq = strchr(elem, '=');
			int taglen=eq ? eq-elem : strlen(elem);
			if (taglen > 0) {
				struct vdeparms *scan;
				for (scan = parms; scan->tag; scan++) {
					if (strncmp(elem, scan->tag, taglen) == 0) {
						*(scan->value)=eq ? eq+1 : "";
						break;
					}
				}
				if (scan->tag == NULL) {
					if (eq == NULL && parms->tag != NULL && parms->tag[0] == 0)
						*(parms->value) = elem;
					else {
						fprintf(stderr, "unknwown key: %*.*s\n", taglen, taglen, elem);
						errno = EINVAL;
						return -1;
					}
				}
			}
		}
	}
	return 0;
}

char *vde_parsenestparms(char *str){
	if (*str != 0) {
		char *sp;
		char *bracket;
		strtokq_nostrip_r(str, "{", &sp);
		bracket = strtokq_rev_r(sp, "}");
		return bracket;
	}
	return NULL;
}

#if 0
int main(int argc, char *argv[]) {
	char *portstr="12345";
	char *vnistr="1";
	char *ttlstr="1";
	struct vdeparms parms[] = {{"port", &portstr}, {"vni", &vnistr}, {"ttl", &ttlstr}, {NULL, NULL}};

	printf("%s\n", argv[1]);
	vde_parseparms(argv[1], parms);
	printf("%s\n", argv[1]);

	struct vdeparms *scan;
	for (scan = parms; scan->tag; scan++)
		printf("%s %s\n", scan->tag, *(scan->value));
}
#endif
