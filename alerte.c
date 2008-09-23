/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: alerte.c 124 2006-05-10 21:46:12Z thierry $
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>

#include "arpalert.h"
#include "alerte.h"
#include "log.h"
#include "loadconfig.h"
#include "errmsg.h"
#include "serveur.h"

// alert levels
const char *alert[] = {
	 "0",  "1",  "2",  "3",  "4",  "5",  "6",  "7",  "8",  "9",
	"10", "11", "12", "13", "14", "15", "16", "17", "18", "19"
};

char cmd_exec[2048];

extern int errno;

struct t_pid {
	int pid;
	time_t time;
	struct t_pid *next;
	struct t_pid *prev;
};

// used for allocate pid structur memory
struct t_pid *pid_alloc;

// flag used when an pid is added
int atomic_add;

// unused base
struct t_pid unused_pid;

// used base
struct t_pid used_pid;

void alerte_kill_pid(int);
		  
// pid list initialization 
void alerte_init(void){
	int counter;
	struct t_pid *assign;

	// init used pid chain
	atomic_add = FALSE;
	used_pid.next = &used_pid;
	used_pid.prev = &used_pid;

	// memory allocation for pid
	pid_alloc = (struct t_pid *)malloc(sizeof(struct t_pid) * config[CF_MAXTH].valeur.integer);
	if(pid_alloc == NULL){
		logmsg(LOG_ERR, "[%s, %i] Memory allocation error", __FILE__, __LINE__);
		exit(1);
	}

	// chain all pid in unused base
	assign = &unused_pid;
	counter = 0;
	while(counter < config[CF_MAXTH].valeur.integer){
		assign->next = &pid_alloc[counter];
		pid_alloc[counter].prev = assign;
		assign = assign->next;
		counter++;
	}
	assign->next = &unused_pid;
	unused_pid.prev = assign;

	// check children end
	(void)setsignal(SIGCHLD, alerte_kill_pid);
}

// add a pid to list 
void addpid(int pid){
	struct t_pid *assign;

	atomic_add = TRUE;

	// check if have a free process memory
	if(unused_pid.next == &unused_pid){
		logmsg(LOG_ERR, "[%s %d] Process limit exceeded",
		       __FILE__, __LINE__);
		exit(1);
	}

	// set values
	assign = unused_pid.next;
	assign->pid = pid;
	assign->time = current_time;

	// delete from the unused list
	unused_pid.next->next->prev = &unused_pid;
	unused_pid.next = unused_pid.next->next;
	
	// add at the end of chain
	assign->next = &used_pid;
	assign->prev = used_pid.prev;
	used_pid.prev->next = assign;
	used_pid.prev = assign;

	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Add pid %i at time %d", __FILE__, __LINE__,
	       assign->pid, (unsigned int)assign->time);
	#endif

	atomic_add = FALSE;
}

// delete pid
void delpid(int pid){
	struct t_pid *assign;

	// if pid is currently added, exit the function
	if(atomic_add == TRUE){
		return;
	}
	
	// if no current recorded pid
	if(used_pid.next == &used_pid) {
		return;
	}

	// find pid in pid chain
	assign = &used_pid;
	while(assign->pid != pid) {
		if(assign->next == &used_pid) {
			return;
		}
		assign = assign->next;
	}

	// delete pid from used list
	assign->next->prev = assign->prev;
	assign->prev->next = assign->next;

	// add pid to unused list
	assign->next = unused_pid.next;
	assign->prev = &unused_pid;
	unused_pid.next->prev = assign;
	unused_pid.next = assign;
}

void alerte_kill_pid(int signal){
	int pid;

	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] entering alerte_kill_pid()", __FILE__, __LINE__); 
	#endif

	while(TRUE){
		pid = waitpid(0, NULL, WNOHANG);
		
		// exit if no more child ended
		if(pid == 0 || ( pid == -1 && errno == 10 ) ){
			break;
		}
		
		// check error
		if(pid == -1 && errno != 10){
			logmsg(LOG_ERR, "[%s %d] Error %d: %s",
				__FILE__, __LINE__, errno, strerror(errno));
			break;
		}
	
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %i] pid [%i] ended", __FILE__, __LINE__, pid); 
		#endif
		delpid(pid);
	}

	// set signal
	(void)setsignal(SIGCHLD, alerte_kill_pid);
}

// check validity of pids
void alerte_check(void){
	int return_code;
	int status;
	struct t_pid *check;
	struct t_pid *temp_check;

	// if no current recorded pid
	if(used_pid.next == &used_pid){
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %i] no pid in pid list", __FILE__, __LINE__);
		#endif
		return;
	}

	// check all process
	check = used_pid.next;
	while(check != &used_pid){

		// record next occurance (the actual pointer mybe deleted)
		temp_check = check->next;
	
		// look if process's running
		return_code = waitpid(check->pid, &status, WNOHANG);
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %i] analysing pid %i: remaining time: %i, "
		       "return code = %i",
		       __FILE__, __LINE__, check->pid,
		       config[CF_TIMEOUT].valeur.integer - ( current_time - check->time ), 
				 return_code);
		#endif

		// if time exceeded
		if(current_time - check->time >= config[CF_TIMEOUT].valeur.integer && 
		   return_code == 0 ) {
			logmsg(LOG_ERR, "[%s %i] kill pid %i: running time exceeded",
			       __FILE__, __LINE__, check->pid);

			// kill it
			if(kill(check->pid, 9) < 0){
				logmsg(LOG_ERR, "[%s %i] I can't kill pid %i",
				       __FILE__, __LINE__, check->pid);
			}
		} 
		#ifdef DEBUG
		else {
			logmsg(LOG_DEBUG, "[%s %i] pid %i is not normally running",
			       __FILE__, __LINE__, check->pid);
		}
		#endif

		// if the process is stopped
		if(return_code == -1){
			#ifdef DEBUG
			logmsg(LOG_DEBUG, "[%s %i] pid %i is ended, removing "
			       "from check list",
			       __FILE__, __LINE__, check->pid);
			#endif

			// delete pid from list
			delpid(check->pid);
		}
		
		check = temp_check;
	}
}

// send an alert
void alerte(char *mac, char *ip, char *parm_supp, int alert_level){
	int return_pid;
	int return_code;
		  
	// if the script is not specified, quit function
	if(config[CF_ACTION].valeur.string[0] == 0){
		return;
	}

	if(unused_pid.next == &unused_pid){
		logmsg(LOG_ERR, "[%s %i] Exceed maximun process", __FILE__, __LINE__);
		return;
	}

	#ifdef DEBUG	
	logmsg(LOG_DEBUG, "[%s %i] Launch alert script [%s]", 			
          __FILE__, __LINE__, config[CF_ACTION].valeur.string);
	#endif

	return_pid = fork();
	if(return_pid == -1){
		logmsg(LOG_ERR, "[%s %i] Can't fork", __FILE__, __LINE__);
		exit(1);
	}
	if(return_pid > 0){
		addpid(return_pid);
		return;
	}

	return_code = execlp(config[CF_ACTION].valeur.string, config[CF_ACTION].valeur.string,
	                     mac, ip, parm_supp, alert[alert_level], (char*)0);
	if(return_code < 0){
		logmsg(LOG_ERR, "[%s %i] Error at execution of script [%s], error %i: %s",
		       __FILE__, __LINE__, config[CF_ACTION].valeur.string, errno, errmsg[errno]);
		exit(1);
	}
	exit(0);
}

