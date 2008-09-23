#include "config.h"

#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>

#include "loadconfig.h"
#include "log.h"

void daemonize(void){
	int pid;
	int i;
	
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
	if(i<0){
		logmsg(LOG_ERR, "[%s %i] Can't open /dev/null\n", __FILE__, __LINE__);
	}
	dup(i);
	dup(i);
}

void separe(void){
	struct passwd *pwd = NULL;
	uid_t uid = 0;
	gid_t gid = 0;
	char str[12];
	int fd;

	/* lock file */
	fd = open(config[CF_LOCKFILE].valeur.string, O_RDWR | O_CREAT, 0640);
	if(fd < 0){
		logmsg(LOG_ERR, "[%s %i] I can't create lock file: %s",
			__FILE__, __LINE__, config[CF_LOCKFILE].valeur.string);
		exit(1);
	}
	if(lockf(fd, F_TLOCK, 0)<0){
		logmsg(LOG_ERR, "[%s %i] daemon instance already running", __FILE__, __LINE__);
		exit(1);
	}
	snprintf(str, 12, "%d\n", getpid());
	write(fd, str, strlen(str));

	/* privilege separation */
	if(config[CF_USER].valeur.string[0] != 0) { 
		if ((pwd = getpwnam(config[CF_USER].valeur.string)) == 0){
			logmsg(LOG_ERR, "[%s %i] unknown user: %s",
				__FILE__, __LINE__, config[CF_USER].valeur.string);
			exit(1);
		}
		if (setgid(gid) < 0){
			logmsg(LOG_ERR, "[%s %i] setgid(%ld) error", __FILE__, __LINE__, (long) gid);
			exit(1);
		}  
		if (initgroups(config[CF_USER].valeur.string, gid) < 0){
			logmsg(LOG_ERR, "[%s %i] initgroups error", __FILE__, __LINE__);
			exit(1);
		}
	}

	/* chroot */
	if (config[CF_CHROOT].valeur.string[0] != 0) {
		if (chroot(config[CF_CHROOT].valeur.string)){
			logmsg(LOG_ERR, "[%s %i] Problem with chroot", __FILE__, __LINE__);
			exit(1);
		}
		if (chdir("/")){
			logmsg(LOG_ERR, "[%s %i] Problem with chdir", __FILE__, __LINE__);
			exit(1);
		}
	}	
	/* change user */
	if(config[CF_USER].valeur.string[0] != 0) {
		if (setuid(uid) < 0){
			logmsg(LOG_ERR, "[%s %i] setuid(%ld) error", __FILE__, __LINE__, (long) uid);
			exit(1);
		}
	}

	/* write rights */
	umask(config[CF_UMASK].valeur.integer);
}

void (*setsignal (int signal, void (*function)(int)))(int) {    
	struct sigaction old, new;

	memset(&new, 0, sizeof(struct sigaction));
	new.sa_handler = function;
	new.sa_flags = SA_RESTART;
	sigemptyset(&(new.sa_mask));
	if (sigaction(signal, &new, &old)){ 
		logmsg(LOG_ERR, "[%s %i] Error when setting signal %i", __FILE__, __LINE__, signal);
		exit(1);
	}
	return(old.sa_handler);
}


