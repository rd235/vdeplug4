#ifndef VDE_PLUG_LOG_H
#define VDE_PLUG_LOG_H

extern char sshremotehost[256];
extern char *username;

void vdeplug_openlog(char *message);

void vdeplug_closelog(void);

#endif
