#ifndef VDE_PLUG_H
#define VDE_PLUG_H

#define MAXDESCR 128
#define CONNECTED_P2P

#include <libvdeplug.h>

struct vdeplug_module; 
struct vdeconn {
	void *handle;
	struct vdeplug_module *module;
	unsigned char data[];
};

struct vdeplug_module {
	int flags;
	VDECONN *(* vde_open_real)(char *given_vde_url, char *descr,int interface_version,
			    struct vde_open_args *open_args);
	ssize_t (* vde_recv)(VDECONN *conn,void *buf,size_t len,int flags);
	ssize_t (* vde_send)(VDECONN *conn,const void *buf,size_t len,int flags);
	int (* vde_datafd)(VDECONN *conn);
	int (* vde_ctlfd)(VDECONN *conn);
	int (* vde_close)(VDECONN *conn);
};

struct vdeparms {
	char *tag;
	char **value;
};

int vde_parseparms(char *str,struct vdeparms *parms);
int vde_parsepathparms(char *str,struct vdeparms *parms);

unsigned long long strtoullm(const char *numstr);

gid_t vde_grnam2gid(const char *name);
	 
#endif
