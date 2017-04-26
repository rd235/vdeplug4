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

VDECONN *vde_open_module(char *modname, char *vde_url, char *descr,int interface_version,
		    struct vde_open_args *open_args) {
	void *handle=dlopen(modname, RTLD_NOW | RTLD_DEEPBIND);

	if (handle) {
		struct vdeplug_module *module=dlsym(handle,"vdeplug_ops");
		if (module) {
			size_t vde_url_len = strlen(vde_url);
			char vde_url_copy[vde_url_len+1];
			strcpy(vde_url_copy, vde_url);
			VDECONN *rv = module->vde_open_real(vde_url_copy, descr, interface_version, open_args);
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

VDECONN *vde_open_real(char *given_vde_url, char *descr,int interface_version,
		    struct vde_open_args *open_args)
{
	char std_vde_url[PATH_MAX];
	struct stat statbuf;
	char newdescr[MAXDESCR];
	int descrlen;
	struct passwd *callerpwd;
	char *ssh_client = getenv("SSH_CLIENT");
	int pid = getpid();
	char *tag;

	if (given_vde_url == NULL)
		given_vde_url = "";

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

	if (*given_vde_url == '\0') {
		char *homedir = getenv("HOME");
		if (homedir) {
			char *stdswitch;
			if (asprintf(&stdswitch, "%s%s", homedir, STDSWITCH) >= 0) {
				if (readlink(stdswitch,std_vde_url,PATH_MAX) >= 0)
					given_vde_url=std_vde_url;
				free(stdswitch);
			}
		}
	}
	if (lstat(given_vde_url,&statbuf) >= 0) {
		if (S_ISREG(statbuf.st_mode)) {
			FILE *f=fopen(given_vde_url,"r");
			if (f != NULL) {
				if (fgets(std_vde_url,PATH_MAX,f) != NULL) {
					std_vde_url[strlen(std_vde_url)-1] = 0;
					given_vde_url=std_vde_url;
				}
				fclose(f);
			}
		}
	}
	if (given_vde_url == NULL || (tag=strstr(given_vde_url,"://")) == NULL) {
		return vde_open_module(DEFAULT_MODULE, given_vde_url, newdescr,
				interface_version, open_args);
	} else {
		int modlen=tag-given_vde_url;
		char modname[modlen+15];
		snprintf(modname, modlen+15, "libvdeplug_%*.*s.so", modlen, modlen, given_vde_url);
		return vde_open_module(modname,given_vde_url+(modlen+3),newdescr,
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
