#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <malloc.h>
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

/* intervalle entre deux checkpoint 
 * le 0 desactve le dump regulier */
#define CHECKPOINT 1

void die(int);
void loadconfig(int);
void setsignal(int, void *);
void dumpmaclist(int);
void killchild(int);

int dumptime;
int nettoyage;

int main(int argc, char **argv){
	/* Copie des parametre e la lignes de commande pour analyse lors d'un rechargement de la config */
	margc = argc;
	margv = argv;
	dumptime = 0;
	nettoyage = 0;
	flagdump = TRUE;
	
	/* va lire le fichier de configuration */
	config_init();
	config_load();
	
	/* si il le faut, passer le binaire en daemon */
	if(config[CF_DAEMON].valeur.integer == TRUE) daemonize();

	/* mise en place des signaux */
	setsignal(SIGINT, (void *)&die);
	setsignal(SIGTERM, (void *)&die);
	setsignal(SIGQUIT, (void *)&die);
	setsignal(SIGABRT, (void *)&die);
	setsignal(SIGHUP, (void *)&loadconfig); 
	setsignal(SIGALRM, (void *)&dumpmaclist);
	if(config[CF_ACTION].valeur.string[0]!=0){
		setsignal(SIGCHLD, (void *)&killchild);
	}

	/* initialisation de la structure mac */
	data_init();

	/* INIT DES ALERTES */
	if(config[CF_ACTION].valeur.string[0]!=0){
		alerte_init();
	}
	
	/* chargement de la maclist */
	maclist_reload();
	
	/* init du compteur d'abus */
	cap_abus();
	
	/* initilidation du sniffeur */
	cap_init();
	
	/* declenchement des alarmes (dump database) */
	alarm(CHECKPOINT);
	
	/* boucle principale */
	cap_snif();

	/* nettoyage des zones memoires */
	data_close();
	
	/* valeur de retour */
	return(0);
}

void die(int signal){
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] End with signal: %i\n", __FILE__, __LINE__, signal);
	#endif
	data_close();
	exit(0);
}

void killchild(int signal){
	alerte_kill_pid();
}

void loadconfig(int signal){
	maclist_reload();
}

void dumpmaclist(int signal){
	/* dump toutes les 5s si demande active */
	if((time(NULL) - dumptime) > 5){
		if(flagdump == TRUE){
			#ifdef DEBUG 
			logmsg(LOG_DEBUG, "[%s %i] Signal %i: dump database\n", __FILE__, __LINE__, signal);
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

void setsignal(int signal, void *function){
	struct sigaction *new;

	new = (struct sigaction *)malloc(sizeof(struct sigaction));
	(*new).sa_handler = (__sighandler_t)function;
	
	if (sigaction(signal, new, NULL)){
		logmsg(LOG_ERR, "[%s %i] Error when setting signal %i\n", __FILE__, __LINE__, signal);
		exit(1);
	}
}
