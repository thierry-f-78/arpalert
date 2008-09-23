#include <fcntl.h>
#include <signal.h>
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
	/* Copie des parametre e la lignes de commande pour analyse lors d'un rechargement de la config */
	margc = argc;
	margv = argv;
	flagdump = TRUE;
	
	/* va lire le fichier de configuration */
	config_load();

	/* si il le faut, passer le binaire en daemon */
	if(config[CF_DAEMON].valeur.integer == TRUE) daemonize();

	/* mise en place des signaux */
	(void)setsignal(SIGINT,  die);
	(void)setsignal(SIGTERM, die);
	(void)setsignal(SIGQUIT, die);
	(void)setsignal(SIGABRT, die);
	(void)setsignal(SIGHUP,  loadconfig); 
	(void)setsignal(SIGALRM, dumpmaclist);
	/*
	if(config[CF_ACTION].valeur.string[0]!=0){
		(void)setsignal(SIGCHLD, killchild);
	}
	*/

	/* initialisation de la structure mac */
	data_init();
	sens_init();

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
	cap_snif();
	
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
}

void dumpmaclist(int signal){
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

	/* nettoyage toutes les 5 minutes */
	if((time(NULL) - nettoyage) >= 60){
		data_clean(config[CF_TOOOLD].valeur.integer);
		nettoyage = time(NULL);
	}

	alerte_check();
	cap_abus();
	alarm(CHECKPOINT);
}

