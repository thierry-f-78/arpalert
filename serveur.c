#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "loadconfig.h"
#include "log.h"

void daemonize(void){
	int pid;
	int i;
	int fd;
	char str[12];
	
	pid = fork();
	if(pid < 0){
		logmsg(LOG_ERR, "[%s %i] I cant exec the first fork", __FILE__, __LINE__);
	}
	if(pid > 0){
		exit(0);
	}

	setsid();

	pid = fork();
	if(pid < 0){
		logmsg(LOG_ERR, "[%s %i] I cant exec the second fork", __FILE__, __LINE__);
	}
	if(pid > 0){
		exit(0);
	}

	/* Ferme les descripteur de fichiers */
	close(0);
	close(1);
	close(2);

	/* ouvre les sortie standard (descripteurs 0 1 2) sur /dev/null */
	i = open("/dev/null", O_RDWR);
	dup(i);
	dup(i);

	umask(0);
	chdir("/tmp");

	fd = open(config[CF_LOCKFILE].valeur.string, O_RDWR | O_CREAT, 0640);
	if(fd < 0){
		logmsg(LOG_ERR, "[%s %i] I can't create lock file: %s", __FILE__, __LINE__, config[CF_LOCKFILE].valeur.string);
		exit(1);
	}
	if(lockf(fd, F_TLOCK, 0)<0){
		logmsg(LOG_ERR, "[%s %i] daemon already running", __FILE__, __LINE__);
		exit(1);
	}

	snprintf(str, 12, "%d\n", getpid());
	write(fd, str, strlen(str));
}
