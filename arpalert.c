/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: arpalert.c 86 2006-05-09 07:43:38Z thierry $
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
#include <unistd.h>
#include <time.h>

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

// system check every seconds
#define CHECKPOINT 1

void die(int);
void loadconfig(int);
void dumpmaclist(int);
/* void killchild(int); */
/* void setsignal(int, void *); */
/* void (*setsignal (int, void (*)(int)))(int); */

int dumptime = 0;
int nettoyage = 0;

int main(int argc, char **argv){
	
	// init current_time
	current_time = time(NULL);
	
	flagdump = TRUE;
	
	// read config file
	config_load(argc, argv);
	
	// log system initialization
	initlog();
	
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
	(void)setsignal(SIGALRM, dumpmaclist);

	// mac sturcturs initialization
	data_init();
	sens_init();

	// sens_timeouts initializations
	if(config[CF_UNAUTH_TO_METHOD].valeur.integer == 2){
		sens_timeout_init();
	}
	
	// alert
	if(config[CF_ACTION].valeur.string[0]!=0){
		alerte_init();
	}

	// load maclist
	maclist_reload();

	// init abuse counter
	cap_abus();

	// launch 1 second check
	alarm(CHECKPOINT);

	// main boucle
	cap_sniff();

	exit(1);
}

void die(int signal){
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] End with signal: %i", __FILE__, __LINE__, signal);
	#endif
	exit(0);
}

void loadconfig(int signal){
	maclist_reload();
	sens_reload();
}

void dumpmaclist(int signal){
	#ifdef DEBUG 
	logmsg(LOG_DEBUG, "[%s %i] entering dumpmaclist. 1s ...", __FILE__, __LINE__);
	#endif
	current_time = time(NULL);

	/* dump toutes les 5s si demande active */
	if(
		current_time - dumptime > 5 &&
		flagdump == TRUE
	){
		#ifdef DEBUG 
		logmsg(LOG_DEBUG, "[%s %i] Signal %i: dump database", __FILE__, __LINE__, signal);
		#endif
		data_dump();
		flagdump = FALSE;
		dumptime = current_time;
	}

	/* nettoyage toutes les minutes */
	if((current_time - nettoyage) >= 60){
		data_clean(config[CF_TOOOLD].valeur.integer);
		nettoyage = current_time;
	}

	/* clean timeouts */
	if(config[CF_UNAUTH_TO_METHOD].valeur.integer == 2){
		sens_timeout_clean();
	}
	
	alerte_check();
	cap_abus();
	alarm(CHECKPOINT);
}

