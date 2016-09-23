/* 
 * Copyright (C) 2003-2016  Renzo Davoli, University of Bologna
 * 
 * dpipe: dual pipe
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <sys/wait.h>

#include <selfsighandler.h>
#include <openclosepidfile.h>

#define DAEMONIZE      0x1
#define NO_WRAPPROC    0x2
#define CLEANUP_NEEDED 0x4
#define NO_CLEANUP     0x8

#if 0
/* debug */
#define execvp(X,Y) \
	({ char **y; \
	 fprintf(stderr,"execvp \"%s\" -",(X)); \
	 for (y=(Y); *y != NULL; y++) \
	 fprintf(stderr,"\"%s\"",*y); \
	 fprintf(stderr,"\n"); \
	 sleep (10); \
	 })
#endif

static char *progname;
pid_t lastpid = -1;

static void cleanup(void)
{
	openclosepidfile(NULL);
	openclosepgrpfile(NULL);
}

static void sigcleanup(void)
{
	cleanup();
	if (lastpid >= 0)
		kill(lastpid,SIGTERM);
}

int waitfortermination(pid_t last) {
	int status;
	int rval = -1;
	pid_t pid;
	lastpid = last;
	while ((pid = waitpid(-1, &status, 0)) >= 0) {
		if (pid == last)
			rval = WEXITSTATUS(status);
	}
	return rval;
}


/* return the index of the next '=' (maybe with { } before or after)
	 if there is { or } before =, this must match dirchar i.e. the 
	 symbol following the previous =
	 dirchar is updated for the next split. */
int splitindex(int argc, char *argv[], int *dirchar) 
{
	register int i;

	for (i=0; i<argc; i++) {
		if (*dirchar == argv[i][0] && argv[i][1] == '=' ) {
			(argv[i])++;*dirchar=0;
		}
		if (argv[i][0] == '=') {
			if (argv[i][1] == '}' || argv[i][1] == '{')
				*dirchar=argv[i][1];
			break;
		}
	}
	return i;
}

void usage_and_exit()
{
	fprintf(stderr,"Usage:\n"
			"  %s [OPTIONS} cmd1 [arg1...] = cmd2 [arg2...] [ = cmd3 [arg3...] ]\n"
			"    using: ... =} cmd [arg] }= ...\n"
			"       or: ... ={ cmd [arg] {= ...\n"
			"    instead of ... = cmd [arg] = ...\n"
			"  means that the intermediate command processes data flowing in one direction only\n"
			"  (left to right, or right to left respectively as indicated by the brackets)\n"
			"OPTIONS:\n"
			"  -p PIDFILE | --pidfile PIDFILE     write process id to PIDFILE\n"
			"  -P PGRPFILE | --pgrpfile PGRPFILE  write process group id to PIDFILE\n"
			"  -d | --daemon                      daemonize the process group\n"
			"  -n | --nowrapproc                  do not create the dpipe parent process\n"
			"  -N | --nowrapnoclean               -n and do not remove pid/pgrp file\n"
			"  -h | --help                        show this short summary\n"
			,progname);
	kill(-getpgrp(),SIGTERM);
	exit (-1);
}

/* alternate_stdin and alternate_stdout are the first available
	 file descriptors. Usually they are 3 and 4. THe code is general
	 and updates two env variables */
static int alternate_stdin;
static int alternate_stdout;
static void alternate_fd()
{
	char numstr[10];
	alternate_stdin=open("/dev/null",O_RDONLY);
	alternate_stdout=open("/dev/null",O_RDONLY);
	close(alternate_stdin);
	close(alternate_stdout);
	snprintf(numstr,10,"%d",alternate_stdin);
	setenv("ALTERNATE_STDIN",numstr,1);
	snprintf(numstr,10,"%d",alternate_stdout);
	setenv("ALTERNATE_STDOUT",numstr,1);
}

pid_t rec_dpipe(int argc, char *argv[],int olddirchar,unsigned int flags) 
{
	int split;
	int newdirchar=olddirchar;

	split=splitindex(argc,argv,&newdirchar);
	/* if this is the final command of the chain */
	if (split >= argc) {
		pid_t last;
		if (newdirchar != 0)
			usage_and_exit();
		if (flags & NO_WRAPPROC) {
			if ((flags & CLEANUP_NEEDED) && fork() == 0) {
				pid_t ppid = getppid();
				close(STDIN_FILENO);
				close(STDOUT_FILENO);
				while (1) {
					if (kill(ppid,0) < 0)
						break;
					sleep(1);
				}
				exit(0);
			} else {
				execvp(argv[0],argv);
				exit(127);
			}
		} else {
			if ((last = fork()) == 0) {
				execvp(argv[0],argv);
				exit(127);
			} else {
				close(STDIN_FILENO);
				close(STDOUT_FILENO);
				return last;
			}
		}
	} else {
		/* the chain has more than one elements. */
		char **argv1,**argv2;
		int p1[2],p2[2];

		if (argc < 3 || split == 0 || split == argc-1) 
			usage_and_exit();

		if (pipe(p1) < 0) {
			perror("pipe");
			exit(1);
		}

		/* ..chain already processed.. = this =....
			 two pipes needed */
		if (olddirchar == 0) {
			if (pipe(p2) < 0) {
				perror("second pipe");
				exit(1);
			}
		}

		argv[split]=NULL;
		argv1=argv;
		argv2=argv+(split+1);

		if (fork() == 0) {
			/* child prepare to run the program */
			switch (olddirchar) {
				case 0:
					/* ... = this = ... */
					close(p1[1]); close(p2[0]);
					if (p1[0] != alternate_stdin){
						dup2(p1[0],alternate_stdin);
						close(p1[0]);
					}
					if (p2[1] != alternate_stdout){
						dup2(p2[1],alternate_stdout);
						close(p2[1]);
					}
					break;
				case '{':
					/* ... ={ this {= ... */
					close(p1[1]);
					dup2(p1[0],STDIN_FILENO);
					close(p1[0]);
					break;
				case '}':
					/* ... =} this }= ... */
					close(p1[0]);
					dup2(p1[1],STDOUT_FILENO);
					close(p1[1]);
					break;
				default:
					fprintf(stderr,"Error\n");
			}
			execvp(argv1[0],argv1);
			exit(127);
		} else {
			/* parent rename the pipes as STDIN_FILENO and STDOUT_FILENO
				 and process the remaining part of the chain */
			switch (olddirchar) {
				case 0:
					/* ... = this = ... */
					close(p2[1]); close(p1[0]);
					dup2(p2[0],STDIN_FILENO);
					dup2(p1[1],STDOUT_FILENO);
					close(p2[0]); close(p1[1]);
					break;
				case '{':
					/* ... ={ this {= ... */
					close(p1[0]);
					dup2(p1[1],STDOUT_FILENO);
					close(p1[1]);
					break;
				case '}':
					/* ... =} this }= ... */
					close(p1[1]);
					dup2(p1[0],STDIN_FILENO);
					close(p1[0]);
					break;
				default:
					fprintf(stderr,"Error\n");
			}
			return rec_dpipe(argc-split-1,argv2,newdirchar,flags);
		}
	}
	return 0;
}

/* start the first process of the dpipe chain */
pid_t start_dpipe(int argc, char *argv[], unsigned int flags)
{
	int split;
	char **argv1,**argv2;
	int p1[2],p2[2];
	int dirchar=0;

	alternate_fd();
	split=splitindex(argc,argv,&dirchar);

	if (argc < 3 || split == 0 || split >= argc-1) 
		usage_and_exit();

	if (pipe(p1) < 0 || pipe(p2) < 0) {
		perror("pipe");
		exit(1);
	}

	argv[split]=NULL;
	argv1=argv;
	argv2=argv+(split+1);

	if (fork() == 0) {
		close(p1[1]); close(p2[0]);
		dup2(p1[0],STDIN_FILENO);
		dup2(p2[1],STDOUT_FILENO);
		close(p1[0]); close(p2[1]);
		execvp(argv1[0],argv1);
		exit(127);
	} else {
		close(p2[1]); close(p1[0]);
		dup2(p2[0],STDIN_FILENO);
		dup2(p1[1],STDOUT_FILENO);
		close(p1[1]); close(p2[0]);
		return rec_dpipe(argc-split-1,argv2,dirchar,flags);
	}
}

char *short_options = "+dp:P:hnN";
struct option long_options[] = {
	{"nowrapproc",    no_argument,       0,  'n' },
	{"nowrapnoclean", no_argument,       0,  'N' },
	{"pidfile",       required_argument, 0,  'p' },
	{"pgrpfile",      required_argument, 0,  'P' },
	{"daemon",        no_argument,       0,  'd' },
	{"help",          no_argument,       0,  'h' },
	{0, 0, 0, 0}
};

int main(int argc, char *argv[]) 
{
	unsigned int flags = 0;
	char *pidfile = NULL;
	char *pgrpfile = NULL;
	int rval;

	progname = argv[0];

	while (1) {
		int option_index = 0;
		int c;
		c = getopt_long(argc, argv, short_options,
				long_options, &option_index);
		if (c == -1) break;
		switch (c) {
			case 'p' : pidfile = optarg;
								 flags |= CLEANUP_NEEDED;
								 break;
			case 'P' : pgrpfile = optarg;
								 flags |= CLEANUP_NEEDED;
								 break;
			case 'd' : flags |= DAEMONIZE;
								 break;
			case 'n' : flags |= NO_WRAPPROC;
								 break;
			case 'N' : flags |= NO_WRAPPROC | NO_CLEANUP;
								 break;
			case 'h' : usage_and_exit();
		}
	}

	if (flags & NO_CLEANUP)
		flags &= ~CLEANUP_NEEDED;
	argc -= optind;
	argv += optind;

	if ((flags & DAEMONIZE) != 0) {
		if (daemon(0,0) < 0) {
			fprintf(stderr,"%s daemonize: %s\n", progname, strerror(errno));
			exit(1);
		}
	} else if (setpgrp() != 0) {
		fprintf(stderr,"Err: cannot create pgrp\n");
		exit(1);
	}

	atexit(cleanup);
	setsighandlers(sigcleanup);

	if (pidfile != NULL) 
		openclosepidfile(pidfile);
	if (pgrpfile != NULL) 
		openclosepgrpfile(pgrpfile);

	rval = waitfortermination(start_dpipe(argc, argv, flags));

	return rval;
}
