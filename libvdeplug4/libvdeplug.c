/*
 * libvdeplug - A library to connect to a VDE Switch.
 * Copyright (C) 2013-2016 Renzo Davoli, University of Bologna
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
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pwd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libvdeplug.h>
#include "libvdeplug_mod.h"

/* Per-User standard switch definition */
/* This will be prefixed by getenv("HOME") */
/* it can be a symbolic link to the switch dir */
#define STDSWITCH "/.vde2/default.switch"

#define DEFAULT_MODULE "libvdeplug_vde.so"

VDECONN *vde_open_module(char *modname, char *sockname, char *descr,int interface_version,
		    struct vde_open_args *open_args) {
	void *handle=dlopen(modname, RTLD_NOW);
	if (handle) {
		struct vdeplug_module *module=dlsym(handle,"vdeplug_ops");
		if (module) {
			VDECONN *rv = module->vde_open_real(sockname, descr, interface_version, open_args);
			if (rv) {
				rv->handle = handle;
				rv->module = module;
				return rv;
			}
		} else
			errno = EPROTONOSUPPORT;
		dlclose(handle);
	} else
		errno = EPROTONOSUPPORT;
	return NULL;
}

VDECONN *vde_open_real(char *given_sockname, char *descr,int interface_version,
		    struct vde_open_args *open_args)
{
	char std_sockname[PATH_MAX];
	struct stat statbuf;
	char newdescr[MAXDESCR];
	int descrlen;
	struct passwd *callerpwd;
	char *ssh_client = getenv("SSH_CLIENT");
	int pid = getpid();
	char *tag;

	if (given_sockname == NULL)
		given_sockname = "";

	callerpwd=getpwuid(getuid());

	descrlen=snprintf(newdescr,MAXDESCR,"%s user=%s PID=%d",
			descr,(callerpwd != NULL)?callerpwd->pw_name:"??",
			pid);

	if (ssh_client) {
		char *endofip=strchr(ssh_client,' ');
		if (endofip) *endofip=0;
		descrlen+=snprintf(newdescr+descrlen,MAXDESCR-descrlen,
				" SSH=%s", ssh_client);
		if (endofip) *endofip=' ';
	}

	if (*given_sockname == '\0') {
		char *homedir = getenv("HOME");
		if (homedir) {
			char *stdswitch;
			if (asprintf(&stdswitch, "%s%s", homedir, STDSWITCH) >= 0) {
				if (readlink(stdswitch,std_sockname,PATH_MAX) >= 0)
					given_sockname=std_sockname;
				free(stdswitch);
			}
		}
	}
	if (lstat(given_sockname,&statbuf) >= 0) {
		if (S_ISREG(statbuf.st_mode)) {
			FILE *f=fopen(given_sockname,"r");
			if (f != NULL) {
				if (fgets(std_sockname,PATH_MAX,f) != NULL) {
					std_sockname[strlen(std_sockname)-1] = 0;
					given_sockname=std_sockname;
				}
				fclose(f);
			}
		}
	}
	if (given_sockname == NULL || (tag=strstr(given_sockname,"://")) == NULL) {
		return vde_open_module(DEFAULT_MODULE, given_sockname, newdescr,
				interface_version, open_args);
	} else {
		int modlen=tag-given_sockname;
		char modname[modlen+15];
		snprintf(modname, modlen+15, "libvdeplug_%*.*s.so", modlen, modlen, given_sockname);
		return vde_open_module(modname,given_sockname+(modlen+3),newdescr,
				                                            interface_version, open_args);
	}
}

ssize_t vde_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	if (__builtin_expect(conn!=0,1)) 
		return conn->module->vde_recv(conn,buf,len,flags);
	else {
		errno=EBADF;
		return -1;
	}
}

ssize_t vde_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	if (__builtin_expect(conn!=0,1)) 
		return conn->module->vde_send(conn,buf,len,flags);
	else {
		errno=EBADF;
		return -1;
	}
}

int vde_datafd(VDECONN *conn)
{
	if (__builtin_expect(conn!=0,1))
		return conn->module->vde_datafd(conn);
	else {
		errno=EBADF;
		return -1;
	}
}

int vde_ctlfd(VDECONN *conn)
{
	if (__builtin_expect(conn!=0,1))
		return conn->module->vde_ctlfd(conn);
	else {
		errno=EBADF;
		return -1;
	}
}

int vde_close(VDECONN *conn)
{
	if (__builtin_expect(conn!=0,1)) {
		void *handle=conn->handle;
		/* vde_close frees the struct conn */
		int rv=conn->module->vde_close(conn);
		if (rv==0) dlclose(handle);
		return rv;
	} else {
		errno=EBADF;
		return -1;
	}
}
