/* 
 * Copyright (C) 2016  Renzo Davoli, University of Bologna
 * 
 * openclosepidfile
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
#include <unistd.h>
#include <openclosepidfile.h>

void openclosepidfile(char *pidfile) {
	static char *savepidfile;
	if (pidfile != NULL) {
		FILE *f = fopen(pidfile,"w");
		if (f != NULL) {
			savepidfile = pidfile;
			fprintf(f,"%d\n", getpid());
			fclose(f);
		}
	} else if (savepidfile != NULL)
		unlink(savepidfile);
}

void openclosepgrpfile(char *pidfile) {
	static char *savepidfile;
	if (pidfile != NULL) {
		FILE *f = fopen(pidfile,"w");
		if (f != NULL) {
			savepidfile = pidfile;
			fprintf(f,"-%d\n", getpgrp());
			fclose(f);
		}
	} else if (savepidfile != NULL)
		unlink(savepidfile);
}

