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
#define STDSWITCH "/.vdeplug/default"
#define OLDSTDSWITCH "/.vde2/default.switch"

#define STD_LIB_PATH "/lib:/usr/lib"
#define LIBVDEPLUG "libvdeplug_"
#define LIBVDEPLUGIN "/vdeplug/" LIBVDEPLUG

#define DEFAULT_MODULE "vde"
uint64_t __vde_version_tag = 4;

struct vde_open_parms {
	char *vde_args;
	char *descr;
	int interface_version;
	struct vde_open_args *open_args;
};

static VDECONN *vde_open_module_lib(char *filename, struct vde_open_parms *parms) {
	void *handle=dlopen(filename, RTLD_NOW | RTLD_DEEPBIND);

	//printf("TRY %s %s\n", filename, parms->vde_args);
	if (handle) {
		struct vdeplug_module *module=dlsym(handle, "vdeplug_ops");
		if (module) {
			VDECONN *rv = module->vde_open_real(parms->vde_args, parms->descr, parms->interface_version, parms->open_args);
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

static VDECONN *vde_open_samedir(char *modname, char *subdir, struct vde_open_parms *parms) {
	char path[PATH_MAX];
	Dl_info info;
	if (dladdr(&__vde_version_tag, &info) != 0) {
		const char *libpath = info.dli_fname;
		char *slash = strrchr(libpath, '/');
		if (slash) {
			int len = slash - libpath;
			snprintf(path, PATH_MAX, "%*.*s%s%s.so",
					len, len, libpath, subdir, modname);
			return vde_open_module_lib(path, parms);
		}
	}
	return errno = EPROTONOSUPPORT, NULL;
}

static VDECONN *vde_open_dirlist(char *modname, char *dirlist, char *subdir, struct vde_open_parms *parms) {
	char path[PATH_MAX];
	VDECONN *retval;
	if (dirlist) {
		while (*dirlist != 0) {
			int len = strchrnul(dirlist, ':') - dirlist;
			snprintf(path, PATH_MAX, "%*.*s%s%s.so",
					len, len, dirlist, subdir, modname);
			retval = vde_open_module_lib(path, parms);
			if (retval != NULL || errno != EPROTONOSUPPORT)
				return retval;
			dirlist += len + (dirlist[len] == ':');
		}
	}
	return errno = EPROTONOSUPPORT, NULL;
}

static VDECONN *vde_open_default(char *modname, struct vde_open_parms *parms) {
	char path[PATH_MAX];
	snprintf(path, PATH_MAX, LIBVDEPLUG "%s.so", modname);
	return vde_open_module_lib(path, parms);
}

static VDECONN *vde_open_module(char *modname, struct vde_open_parms *parms) {
	char *vdeplugin_path = getenv("VDEPLUGIN_PATH");
	// creata a copy of parms->vde_args
	size_t vde_args_len = strlen(parms->vde_args);
	char vde_args_copy[vde_args_len + 1];
	strcpy(vde_args_copy, parms->vde_args);
	parms->vde_args = vde_args_copy;

	// if VDEPLUGIN_PATH exists it defines the search path for plugins
	if (vdeplugin_path)
		return vde_open_dirlist(modname, vdeplugin_path, "/" LIBVDEPLUG, parms);
	else {
		VDECONN *retval;
		retval = vde_open_samedir(modname, LIBVDEPLUGIN, parms);
		if (retval != NULL || errno != EPROTONOSUPPORT) return retval;
		retval = vde_open_samedir(modname, "/" LIBVDEPLUG, parms);
		if (retval != NULL || errno != EPROTONOSUPPORT) return retval;
		retval = vde_open_dirlist(modname, getenv("LD_LIBRARY_PATH"), LIBVDEPLUGIN, parms);
		if (retval != NULL || errno != EPROTONOSUPPORT) return retval;
		retval = vde_open_dirlist(modname, STD_LIB_PATH, LIBVDEPLUGIN, parms);
		if (retval != NULL || errno != EPROTONOSUPPORT) return retval;
		return vde_open_default(modname, parms);
	}
}

static inline size_t getpw_bufsize(void) {
	size_t bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	return bufsize > 0 ? bufsize : PATH_MAX;
}

static void set_newdescr(const char *descr, char *newdescr, size_t newdescrlen) {
	char *ssh_client = getenv("SSH_CLIENT");
	int pid = getpid();
	uid_t uid = geteuid();
	struct passwd pwd;
	struct passwd *callerpwd;
	size_t bufsize = getpw_bufsize();
	char buf[bufsize];
	FILE *f = fmemopen(newdescr, newdescrlen, "w");

	fprintf(f, "%s ", descr);

	getpwuid_r(uid, &pwd, buf, bufsize, &callerpwd);
	if (callerpwd)
		fprintf(f, "user=%s", callerpwd->pw_name);
	else
		fprintf(f, "user=%d", uid);
	fprintf(f, " pid=%d", pid);

	if (ssh_client) {
		int len = strchrnul(ssh_client,' ') - ssh_client;
		fprintf(f, " SSH=%*.*s", len, len, ssh_client);
	}

	fclose(f);
	newdescr[newdescrlen - 1] = 0;
	//printf("%s %d\n", newdescr, bufsize);
}

VDECONN *vde_open_real(char *vde_url, char *descr, int interface_version,
		struct vde_open_args *open_args)
{
	char std_vde_url[PATH_MAX];
	struct stat statbuf;
	char newdescr[MAXDESCR];
	char *tag;
	struct vde_open_parms parms = {
		.descr = newdescr,
		.interface_version = interface_version,
		.open_args = open_args
	};

	if (vde_url == NULL)
		vde_url = "";

	tag = strstr(vde_url, "://");

	set_newdescr(descr, newdescr, MAXDESCR);

	if (tag == NULL) {
		if (*vde_url == '\0') {
			char *homedir = getenv("HOME");
			if (homedir) {
				snprintf(std_vde_url, PATH_MAX, "%s%s", homedir, STDSWITCH);
				if (lstat(std_vde_url, &statbuf) >= 0)
					vde_url = std_vde_url;
				else {
					snprintf(std_vde_url, PATH_MAX, "%s%s", homedir, OLDSTDSWITCH);
					if (lstat(std_vde_url, &statbuf) >= 0)
						vde_url = std_vde_url;
				}
			}
		}
		if (stat(vde_url, &statbuf) >= 0) {
			if (S_ISREG(statbuf.st_mode)) {
				FILE *f=fopen(vde_url,"r");
				if (f != NULL) {
					if (fgets(std_vde_url, PATH_MAX, f) != NULL) {
						std_vde_url[strlen(std_vde_url) - 1] = 0;
						vde_url = std_vde_url;
					}
					tag = strstr(vde_url, "://");
					fclose(f);
				}
			}
		}
	}
	if (vde_url == NULL || tag == NULL) {
		parms.vde_args = vde_url;
		return vde_open_module(DEFAULT_MODULE, &parms);
	} else {
		int modlen=tag - vde_url;
		char modname[modlen + 1];
		snprintf(modname, modlen + 1, "%*.*s", modlen, modlen, vde_url);
		parms.vde_args = vde_url + (modlen + 3);
		return vde_open_module(modname, &parms);
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
