#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/wait.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include "alerte.h"
#include "log.h"
#include "loadconfig.h"
#include "config.h"
#include "errmsg.h"

char cmd_exec[2048];

typedef struct {
	int	pid;
	time_t	time;
} c_pid;

c_pid *pids;
int num_pids;

/* initilisation de pids */
void alerte_init(void){
	pids = (c_pid *)malloc(sizeof(c_pid));
	num_pids = 0;
	if(pids == NULL){
		logmsg(LOG_ERR, "[%s %i] Can't allocate memory for c_pid struct", __FILE__, __LINE__);
		exit(-1);
        }
}

/* ajout d'un pid a la liste */
void addpid(int pid){
	c_pid *test;

	/* on incremente le nombre d'entree */
	num_pids++;

	/* reallocation de la memoire */
	test = (c_pid *)realloc(pids, num_pids * sizeof(c_pid));
	if(test == NULL){
		logmsg(LOG_ERR, "[%s %i] Can't allocate memory for c_pid struct", __FILE__, __LINE__);
		free(pids);
		exit(1);
	}
	pids = test;

	/* ajout des valeurs */
	pids[num_pids-1].pid = pid;
	pids[num_pids-1].time = time(NULL);
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Add pid %i at position  %i at time %i", __FILE__, __LINE__,
		pids[num_pids-1].pid, num_pids-1, (unsigned int)pids[num_pids-1].time);
	#endif
}

/* supprimer un pid */
void delpid(int pid){
	int i;
	c_pid *b1, *b2, *test;

	/* recopie la table en supprimant l'entree enlevee */
	b1 = pids;
	b2 = pids;
	i = 0;
	num_pids--;
	while(i<num_pids){
		if(b1->pid == pid) b1++;
		b2->pid = b1->pid;
		b2->time = b1->time;
		b1++;
		b2++;
		i++;
	}

	/* si la table n'est pas vide, realloue la memoire */
	if(num_pids>0){
		test = (c_pid *)realloc(pids, num_pids * sizeof(c_pid));
		if(test == NULL){
			logmsg(LOG_ERR, "[%s %i] Can't reallocate memory [%i] for c_pid struct", __FILE__, __LINE__, num_pids * sizeof(c_pid));
			free(pids);
			exit(1);
		}
		pids = test;
	}
}

void alerte_kill_pid(void){
	int ret;
	int i;
	int status;

	i=0;
	while(i < num_pids){
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %i] Start waitpid, record n: %i", __FILE__, __LINE__, i);
		#endif
		ret = waitpid(pids[i].pid, &status, WNOHANG);
		if(ret > 0)delpid(pids[i].pid);
		i++;
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %i] Stop waitpid", __FILE__, __LINE__);
		#endif
	}
}

/* verification des pids */
void alerte_check(void){
	int i;
	int status;
	int ret;

	if(num_pids==0){
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %i] no pid in pid list", __FILE__, __LINE__);
		#endif
		return;
	}

	i = 0;
	while(i < num_pids){
		/* va voir si le processus fonctionne */
		ret = waitpid(pids[i].pid, &status, WNOHANG);
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %i] analyse de pid[%i]: %i, temps: %i, code retour = %i", __FILE__, __LINE__,
			i, pids[i].pid, (unsigned int)pids[i].time, ret);
		#endif

		/* si il fonctionne mais que son temps est depasse */
		if((time(NULL) - pids[i].time >= config[CF_TIMEOUT].valeur.integer) && (ret==0)){
			logmsg(LOG_ERR, "[%s %i] kill pid[%i]: %i", __FILE__, __LINE__, i, pids[i].pid);
			
			/* on le tue */
			if(kill(pids[i].pid, 9) < 0){
				logmsg(LOG_ERR, "[%s %i] I can't kill pid [%i]: %i", __FILE__, __LINE__, i, pids[i].pid);
			} /*else {
				waitpid(pids[i].pid, &status, 0);
				delpid(pids[i].pid);
			}*/
		} 
		#ifdef DEBUG
		else {
			logmsg(LOG_DEBUG, "[%s %i] pid[%i]: %i is not timeout", __FILE__, __LINE__, i, pids[i].pid);
		}
		#endif

		/* si il ne fonctionne plus */
		if(ret==-1){
			#ifdef DEBUG
			logmsg(LOG_DEBUG, "[%s %i] pid[%i]: %i is ended, removing from check list", __FILE__, __LINE__, i, pids[i].pid);
			#endif

			/* on l'efface de la liste */
			delpid(pids[i].pid);
		}
		i++;
	}
}

/* genere une alerte */
int alerte(unsigned char *mac, unsigned char *ip, int alert_level){
	int pid;
	int ret;
	char alert[5];

	/* si le script n'est pas defini on quitte */
	if(config[CF_ACTION].valeur.string[0]==0) return(0);
	
	logmsg(LOG_DEBUG, "[%s %i] Launch alert", __FILE__, __LINE__);

	if(num_pids >= config[CF_MAXTH].valeur.integer){
		logmsg(LOG_ERR, "[%s %i] Exceed maximun process", __FILE__, __LINE__);
		return(-1);
	}

	pid=fork();
	if(pid<0){
		logmsg(LOG_ERR, "[%s %i] I can't fork", __FILE__, __LINE__);
		return(pid);
	}
	if(pid>0){
		addpid(pid);
		return(pid);
	}

	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Attempt to execute \"%s\"", __FILE__, __LINE__, config[CF_ACTION].valeur.string);
	#endif
	
	snprintf(alert, 5, "%i", alert_level);
	ret = execlp(config[CF_ACTION].valeur.string, config[CF_ACTION].valeur.string, mac, ip, alert, NULL);
	if(ret < 0){
		logmsg(LOG_ERR, "[%s %i] Error at execution of \"%s\", error %i: %s", __FILE__, __LINE__,
			config[CF_ACTION].valeur.string, errno, errmsg[errno]);
		exit(1);
	}
	exit(0);
}

