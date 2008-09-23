/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: arpalert.c 313 2006-10-16 12:54:40Z thierry $
 *
 */

#include "config.h"

#include <fcntl.h>
#include <signal.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/select.h>

#include "arpalert.h"
#include "loadconfig.h"
#include "log.h"
#include "data.h"
#include "maclist.h"
#include "capture.h"
#include "serveur.h"
#include "alerte.h"
#include "sens.h"
#include "sens_timeouts.h"
#include "loadmodule.h"
#include "func_time.h"

extern int errno;

void die(int);
void loadconfig(int);
void dumpmaclist(int);

int dumptime = 0;
int nettoyage = 0;

int main(int argc, char **argv){
	fd_set read_filed_set;
	int selret, max_filed;
	void (* check_timeout)(void);
	void (* check_temp)(void);
	struct timeval timeout;
	struct timeval temp_timeout;
	struct timeval cur_timeout;
	struct timeval *tmout;
	
	// init current_time
	//current_time = time(NULL);
	gettimeofday(&current_t, NULL);
	
	// read config file
	config_load(argc, argv);

	// log system initialization
	initlog();
	
	// load module alert
	module_load();

	// pcap initialization
	cap_init();

	// daemonize arpalert
	if(config[CF_DAEMON].valeur.integer == TRUE) daemonize();

	// privilege separation and chrooting
	separe();
	
	// set up signals
	(void)setsignal(SIGINT,  die);
	(void)setsignal(SIGTERM, die);
	(void)setsignal(SIGQUIT, die);
	(void)setsignal(SIGABRT, die);
	(void)setsignal(SIGHUP,  loadconfig); 

	// mac sturcturs initialization
	data_init();
	sens_init();

	// sens_timeouts initializations
	sens_timeout_init();
	
	// alert
	alerte_init();

	// load maclist
	maclist_reload();

	// init abuse counter
	cap_abus();

	// scheduler
	while(TRUE){

		// generate bitfield
		FD_ZERO(&read_filed_set);
		max_filed = cap_gen_bitfield(&read_filed_set);

		// generate timeouts
		cur_timeout.tv_sec = -1;
		check_temp = NULL;
		check_timeout = NULL;

		// check timeout for sens_timeout functions
		if(config[CF_UNAUTH_TO_METHOD].valeur.integer == 2){
			check_temp = sens_timeout_next(&temp_timeout);
			if(temp_timeout.tv_sec != -1){
				if(cur_timeout.tv_sec != -1){
					if(time_comp(&cur_timeout, &temp_timeout) == BIGEST){
						cur_timeout.tv_sec = temp_timeout.tv_sec;
						cur_timeout.tv_usec = temp_timeout.tv_usec;
						check_timeout = check_temp;
					}
				} else {
					cur_timeout.tv_sec = temp_timeout.tv_sec;
					cur_timeout.tv_usec = temp_timeout.tv_usec;
					check_timeout = check_temp;
				}
			}

/*
printf("unauth: %d.%d cur: %d.%d\n",
temp_timeout.tv_sec, temp_timeout.tv_usec,
cur_timeout.tv_sec, cur_timeout.tv_usec);
*/

		}
		

		// check timeout for program lauched
		check_temp = alerte_next(&temp_timeout);
		if(temp_timeout.tv_sec != -1){
			if(cur_timeout.tv_sec != -1){
				if(time_comp(&cur_timeout, &temp_timeout) == BIGEST){
					cur_timeout.tv_sec = temp_timeout.tv_sec;
					cur_timeout.tv_usec = temp_timeout.tv_usec;
					check_timeout = check_temp;
				}
			} else {
				cur_timeout.tv_sec = temp_timeout.tv_sec;
				cur_timeout.tv_usec = temp_timeout.tv_usec;
				check_timeout = check_temp;
			}
		}

/*
printf("proces: %d.%d cur: %d.%d\n",
temp_timeout.tv_sec, temp_timeout.tv_usec,
cur_timeout.tv_sec, cur_timeout.tv_usec);
*/

		// check capture management
		check_temp = cap_next(&temp_timeout);
		if(temp_timeout.tv_sec != -1){
			if(cur_timeout.tv_sec != -1){
				if(time_comp(&cur_timeout, &temp_timeout) == BIGEST){
					cur_timeout.tv_sec = temp_timeout.tv_sec;
					cur_timeout.tv_usec = temp_timeout.tv_usec;
					check_timeout = check_temp;
				}
			} else {
				cur_timeout.tv_sec = temp_timeout.tv_sec;
				cur_timeout.tv_usec = temp_timeout.tv_usec;
				check_timeout = check_temp;
			}
		}

/*
printf("captur: %d.%d cur: %d.%d\n",
temp_timeout.tv_sec, temp_timeout.tv_usec,
cur_timeout.tv_sec, cur_timeout.tv_usec);
*/

		// check data management
		check_temp = data_next(&temp_timeout);
		if(temp_timeout.tv_sec != -1){
			if(cur_timeout.tv_sec != -1){
				if(time_comp(&cur_timeout, &temp_timeout) == BIGEST){
					cur_timeout.tv_sec = temp_timeout.tv_sec;
					cur_timeout.tv_usec = temp_timeout.tv_usec;
					check_timeout = check_temp;
				}
			} else {
				cur_timeout.tv_sec = temp_timeout.tv_sec;
				cur_timeout.tv_usec = temp_timeout.tv_usec;
				check_timeout = check_temp;
			}
		}

/*
printf("data  : %d.%d cur: %d.%d\n",
temp_timeout.tv_sec, temp_timeout.tv_usec,
cur_timeout.tv_sec, cur_timeout.tv_usec);
*/

		// calculate timeout time from the next timeout date
		if(cur_timeout.tv_sec != -1){
			time_sous(&cur_timeout, &current_t, &timeout);

			// prevent negative timeout
			if(timeout.tv_sec < 0){
				timeout.tv_usec = 0;
				timeout.tv_sec = 0;
			}
			// add 10000µs for prevent premature timeout
			timeout.tv_usec += 10000;
			tmout = &timeout;

/*
printf("next time out = %d.%d\n",timeout.tv_sec, timeout.tv_usec);
printf("%d.%d - %d.%d => %d.%d\n",
cur_timeout.tv_sec, cur_timeout.tv_usec,
current_t.tv_sec, current_t.tv_usec,
timeout.tv_sec, timeout.tv_usec);
*/

		} else {
			tmout = NULL;
		}

		// block waiting for next system event or timeout
		selret = select(max_filed + 1, &read_filed_set, NULL, NULL, tmout);

		// maj current hour
		gettimeofday(&current_t, NULL);
	
		// errors:
		if (selret == -1 && errno != EINTR){
			logmsg(LOG_ERR, "[%s %i] select: %s",
			       __FILE__, __LINE__, strerror(errno));
			exit(1);
		}
		
		// timeouts
		if(selret == 0){
			if(check_timeout != NULL){
// printf("%08x at %d.%d\n", check_timeout, current_t.tv_sec, current_t.tv_usec);
				check_timeout();
			}
		}

		// network pcap events
		if(selret > 0){
			cap_sniff(&read_filed_set);
		}
	}

	exit(1);
}

void die(int signal){
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] End with signal: %i",
	       __FILE__, __LINE__, signal);
	#endif

	// close module
	module_unload();
	
	exit(0);
}

void loadconfig(int signal){
	maclist_reload();
	sens_reload();
}

