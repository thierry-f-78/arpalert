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

#include "loadconfig.h"
#include "log.h"
#include "data.h"
#include "maclist.h"
#include "capture.h"
#include "serveur.h"
#include "alerte.h"
#include "sens.h"
#include "sens_timeouts.h"

/* intervalle entre deux checkpoint 
 * le 0 desactve le dump regulier */
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
	flagdump = TRUE;
	
	/* va lire le fichier de configuration */
	config_load(argc, argv);
	
	/* log system initialization */
	initlog();
	
	/* initilaize pcap */
	cap_init();

	/* si il le faut, passer le binaire en daemon */
	if(config[CF_DAEMON].valeur.integer == TRUE) daemonize();

	/* separation des priviliges et chrooting */
	separe();
	
	/* mise en place des signaux */
	(void)setsignal(SIGINT,  die);
	(void)setsignal(SIGTERM, die);
	(void)setsignal(SIGQUIT, die);
	(void)setsignal(SIGABRT, die);
	(void)setsignal(SIGHUP,  loadconfig); 
	(void)setsignal(SIGALRM, dumpmaclist);

	/* initialisation de la structure mac */
	data_init();
	sens_init();

	/* sens_timeouts initializations */
	if(config[CF_UNAUTH_TO_METHOD].valeur.integer == 2){
		sens_timeout_init();
	}
	
	/* INIT DES ALERTES */
	if(config[CF_ACTION].valeur.string[0]!=0){
		alerte_init();
	}

	/* chargement de la maclist */
	maclist_reload();

	/* init du compteur d'abus */
	cap_abus();

	/* declenchement des alarmes (dump database) */
	alarm(CHECKPOINT);

	/* boucle principale */
	cap_sniff();

	exit(1);
}

void die(int signal){
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] End with signal: %i", __FILE__, __LINE__, signal);
	#endif
	data_close();
	sens_free();
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

	/* dump toutes les 5s si demande active */
	if((time(NULL) - dumptime) > 5){
		if(flagdump == TRUE){
			#ifdef DEBUG 
			logmsg(LOG_DEBUG, "[%s %i] Signal %i: dump database", __FILE__, __LINE__, signal);
			#endif
			data_dump();
			flagdump = FALSE;
		}
		dumptime = time(NULL);
	}

	/* nettoyage toutes les minutes */
	if((time(NULL) - nettoyage) >= 60){
		data_clean(config[CF_TOOOLD].valeur.integer);
		nettoyage = time(NULL);
	}

	/* clean timeouts */
	if(config[CF_UNAUTH_TO_METHOD].valeur.integer == 2){
		sens_timeout_clean();
	}
	
	alerte_check();
	cap_abus();
	alarm(CHECKPOINT);
}

