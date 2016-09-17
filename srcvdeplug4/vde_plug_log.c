/* 
 * Copyright (C) 2002-2016  Renzo Davoli, University of Bologna
 * Modified by Ludovico Gardenghi 2005
 * 
 * log: vde_plug logging facilities
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>
#include <ctype.h>
#include <vde_plug_log.h>

char sshremotehost[256];
char *username;

static void vdeplug_getdata(void)
{
	char *ssh_client;
	size_t ip_length;

	//get the login name
	struct passwd *callerpwd = getpwuid(getuid());
	username = callerpwd->pw_name;

	openlog("vde_plug", 0, LOG_USER);

	//get the caller IP address
	//TNX Giordani-Macchia code from vish.c
	if ((ssh_client = getenv("SSH_CLIENT"))!=NULL)
	{
		for (ip_length = 0;
				ip_length<sizeof(sshremotehost) && ssh_client[ip_length] != 0&& !isspace(ssh_client[ip_length]);
				ip_length++)
			;
		if (ip_length>=sizeof(sshremotehost))
			ip_length = sizeof(sshremotehost)-1;
		memcpy(sshremotehost,ssh_client,ip_length);
		sshremotehost[ip_length] = 0;
	}
	else
		strcpy(sshremotehost,"UNKNOWN_IP_ADDRESS");
}

void vdeplug_openlog(char *message) {
	openlog("vde_plug", 0, LOG_USER);
	vdeplug_getdata();
	syslog(LOG_INFO,"%s: user %s IP %s",message ?message : "START",username,sshremotehost);
	if (message) 
		closelog();
}

void vdeplug_closelog(void) {
	syslog(LOG_INFO,"%s: user %s IP %s","STOP",username,sshremotehost);
	closelog();
}

