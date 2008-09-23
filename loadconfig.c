#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include "loadconfig.h"
#include "log.h"

char msg[4096];
int dump = 0;

void miseenforme(char*);
void miseenmemoire(char*);
char lowercase(char);
int convert_int(char*);
int convert_boolean(char*);

void config_load(void){
	char c;
	extern char *optarg;
	extern int optind;
	extern int opterr;
	FILE *fp;
	char buffer[4096];
	char *buf;
	char msgd[512];
	int i;

	/* chargement des valeurs par defaut et definition des entrées */
	config[0].type = 0;
	strncpy(config[0].attrib, "maclist file", 512);
	config[0].valeur.string[0] = 0;
	
	config[1].type = 0;
	strncpy(config[1].attrib, "log file", 512);
	strncpy(config[1].valeur.string, "/dev/null", 1024);
	
	config[2].type = 0;
	strncpy(config[2].attrib, "action on detect", 512);
	config[2].valeur.string[0] = 0;
	
	config[3].type = 0;
	strncpy(config[3].attrib, "lock file", 512);
	strncpy(config[3].valeur.string, PID_FILE, 1024);
	
	config[4].type = 2;
	strncpy(config[4].attrib, "daemon", 512);
	config[4].valeur.integer = FALSE;
	
	config[5].type = 1;
	strncpy(config[5].attrib, "reload interval", 512);
	config[5].valeur.integer = 600;
	
	config[6].type = 1;
	strncpy(config[6].attrib, "log level", 512);
	config[6].valeur.integer = 6;
	
	config[7].type = 1;
	strncpy(config[7].attrib, "execution timeout", 512);
	config[7].valeur.integer = 10;

	config[8].type = 1;
	strncpy(config[8].attrib, "max alert", 512);
	config[8].valeur.integer = 20;

	config[9].type = 0;
	strncpy(config[9].attrib, "maclist alert file", 512);
	config[9].valeur.string[0] = 0;
	
	config[10].type = 0;
	strncpy(config[10].attrib, "maclist leases file", 512);
	config[10].valeur.string[0] = 0;
	
	config[11].type = 0;
	strncpy(config[11].attrib, "interface", 512);
	config[11].valeur.string[0] = 0;

	config[CF_ABUS].type = 1;
	strncpy(config[CF_ABUS].attrib, "max request", 512);
	config[CF_ABUS].valeur.integer = 1000000;
	
	config[CF_MAXENTRY].type = 1;
	strncpy(config[CF_MAXENTRY].attrib, "max entry", 512);
	config[CF_MAXENTRY].valeur.integer = 1048576;	/* 14Mo */
	
	config[CF_DMPWL].type = 2;
	strncpy(config[CF_DMPWL].attrib, "dump white list", 512);
	config[CF_DMPWL].valeur.integer = FALSE;
			
	config[CF_DMPBL].type = 2;
	strncpy(config[CF_DMPBL].attrib, "dump black list", 512);
	config[CF_DMPBL].valeur.integer = FALSE;
		
	config[CF_DMPAPP].type = 2;
	strncpy(config[CF_DMPAPP].attrib, "dump new address", 512);
	config[CF_DMPAPP].valeur.integer = TRUE;
	
	config[CF_TOOOLD].type = 1;
	strncpy(config[CF_TOOOLD].attrib, "mac timeout", 512);
	config[CF_TOOOLD].valeur.integer = 2592000; /* 1 mois */

	config[CF_LOGALLOW].type = 2;
	strncpy(config[CF_LOGALLOW].attrib, "log referenced address", 512);
	config[CF_LOGALLOW].valeur.integer = FALSE;
	
	config[CF_ALRALLOW].type = 2;
	strncpy(config[CF_ALRALLOW].attrib, "alert on referenced address", 512);
	config[CF_ALRALLOW].valeur.integer = FALSE;
	
	config[CF_LOGDENY].type = 2;
	strncpy(config[CF_LOGDENY].attrib, "log deny address", 512);
	config[CF_LOGDENY].valeur.integer = TRUE;
	
	config[CF_ALRDENY].type = 2;
	strncpy(config[CF_ALRDENY].attrib, "alert on deny address", 512);
	config[CF_ALRDENY].valeur.integer = TRUE;

	config[CF_LOGNEW].type = 2;
	strncpy(config[CF_LOGNEW].attrib, "log new address", 512);
	config[CF_LOGNEW].valeur.integer = TRUE;

	config[CF_ALRNEW].type = 2;
	strncpy(config[CF_ALRNEW].attrib, "alert on new address", 512);
	config[CF_ALRNEW].valeur.integer = TRUE;

	config[CF_ALRIP].type = 2;
	strncpy(config[CF_ALRIP].attrib, "alert on ip change", 512);
	config[CF_ALRIP].valeur.integer = TRUE;

	config[CF_LOGIP].type = 2;
	strncpy(config[CF_LOGIP].attrib, "log ip change", 512);
	config[CF_LOGIP].valeur.integer = TRUE;

	config[CF_AUTHFILE].type = 0;
	strncpy(config[CF_AUTHFILE].attrib, "auth request file", 512);
	config[CF_AUTHFILE].valeur.string[0] = 0;

	config[CF_LOG_UNAUTH_RQ].type = 2;
	strncpy(config[CF_LOG_UNAUTH_RQ].attrib, "log unauth request", 512);
	config[CF_LOG_UNAUTH_RQ].valeur.integer = TRUE;

	config[CF_ALERT_UNAUTH_RQ].type = 2;
	strncpy(config[CF_ALERT_UNAUTH_RQ].attrib, "alert on unauth request", 512);
	config[CF_ALERT_UNAUTH_RQ].valeur.integer = TRUE;

	config[CF_LOG_ABUS].type = 2;
	strncpy(config[CF_LOG_ABUS].attrib, "log request abus", 512);
	config[CF_LOG_ABUS].valeur.integer = TRUE;

	config[CF_ALERT_ABUS].type = 2;
	strncpy(config[CF_ALERT_ABUS].attrib, "alert on request abus", 512);
	config[CF_ALERT_ABUS].valeur.integer = TRUE;

	config[CF_LOG_BOGON].type = 2;
	strncpy(config[CF_LOG_BOGON].attrib, "log mac error", 512);
	config[CF_LOG_BOGON].valeur.integer = TRUE;

	config[CF_ALR_BOGON].type = 2;
	strncpy(config[CF_ALR_BOGON].attrib, "alert on mac error", 512);
	config[CF_ALR_BOGON].valeur.integer = TRUE;

	config[CF_IGNORE_UNKNOW].type = 2;
	strncpy(config[CF_IGNORE_UNKNOW].attrib, "ignore unknow sender", 512);
	config[CF_IGNORE_UNKNOW].valeur.integer = TRUE;

	config[CF_DUMP_PAQUET].type = 2;
	strncpy(config[CF_DUMP_PAQUET].attrib, "dump paquet", 512);
	config[CF_DUMP_PAQUET].valeur.integer = FALSE;

	/* cherche / recharge les parametres de la ligne de commande */
	optind = 0;
	strncpy(config_file, CONFIG_FILE, 2048);
	while ((c = getopt(margc, margv, "f:i:p:e:dwD:l:v")) != EOF) {
		switch (c) {
			case 'f': 
				strncpy(config_file, optarg, 2048);
			break;
			
			case 'i':
				strncpy(config[CF_IF].valeur.string, optarg, 1024);
			break;

			case 'p':
				strncpy(config[CF_LOCKFILE].valeur.string, optarg, 1024);
			break;

			case 'e':
				strncpy(config[CF_ACTION].valeur.string, optarg, 1024);
			break;
			
			case 'd':
				config[CF_DAEMON].valeur.integer = TRUE;
			break;

			case 'D':
				if(optarg[0] < 48 || optarg[0] > 55){
					fprintf(stderr, "Parametre -D errone");
					exit(1);
				}
				config[CF_LOGLEVEL].valeur.integer = optarg[0] - 48;
			break;

			case 'l':
				strncpy(config[CF_LEASES].valeur.string, optarg, 1024);
			break;

			case 'v':
				dump = 1;
			break;
			
			case 'w':
				config[CF_DUMP_PAQUET].valeur.integer = TRUE;
			break;
			
			case 'h':
			case '?':
				printf("\n");
				printf("arpalert [-f config_file] [-i network_interface] [-p pid_file] [-e exec_script]\n");
				printf("    [-D log_level] [-l leases_file] [-d][-v][-h]\n");
				printf("\n");
				printf("    -d run as daemon\n");
				printf("    -v dump config\n");
				printf("    -h this help\n");
				printf("\n");
				exit(1);
			break;
		}
	}

	buf = buffer;
	fp = fopen(config_file, "r");
	if(fp == NULL){
		snprintf(msgd, 512, "[%s %i] don't found %s, loading default config\n", __FILE__, __LINE__, config_file);
		fprintf(stderr, msgd);
	} else {
		while((buf = fgets(buf, 4096, fp)) != NULL){
			miseenforme(buf);
			if(buf[0] != 0){
				miseenmemoire(buf);
			}
		}
		fclose(fp);
	}

	if(dump==1){
		for(i=0; i<NUM_PARAMS; i++){
			switch(config[i].type){
				case 0:
					printf("%s = \"%s\"\n", config[i].attrib, config[i].valeur.string);
				break;

				case 1:
					printf("%s = %i\n", config[i].attrib, config[i].valeur.integer);
				break;

				case 2:
					if(config[i].valeur.integer == TRUE){
						printf("%s = TRUE\n", config[i].attrib);
					} else {
						printf("%s = FALSE\n", config[i].attrib);
					}
				break;
			}
		}
	}
}

void miseenmemoire(char *buf){
	char *src = NULL;
	char *m_eq = NULL;
	char *m_end = NULL;
	char m_gauche[4096];
	char m_droite[4096];
	char *gauche = NULL;
	char *droite = NULL;
	char *g = NULL;
	char *d = NULL;
	int i;
	int protection, ok;
	
	gauche = m_gauche;
	droite = m_droite;
	g = gauche;
	d = droite;
	src = buf;

	protection = 0;
	while(*src != 0){
		if(*src == '"'){
			protection ^= 0xff;
			src++;
			continue;
		}
		if(protection != 255 && *src=='=')m_eq=src;
		src++;
	}
	m_end=src;
	if(*m_eq!='='){
		fprintf(stderr, "%i: erreur dans le fichier de config a la ligne: %s\n", __LINE__, buf);
		exit(1);
	}
	if(*(m_eq-1)!=' '){
		fprintf(stderr, "%i: erreur dans le fichier de config a la ligne: %s\n", __LINE__, buf);
		exit(1);
	}
	if(*(m_eq-1)!=' '){
		fprintf(stderr, "%i: erreur dans le fichier de config a la ligne: %s\n", __LINE__, buf);
		exit(1);
	}
	src=buf;
	while(src<(m_eq-1)){
		*gauche=lowercase(*src);
		gauche++;
		src++;
	}
	*gauche=0;
	src+=3;
	if(*src=='"'){
		src++;
		m_end--;
	}
	while(src<m_end){
		*droite=*src;
		droite++;
		src++;
	}
	*droite=0;

	i = 0;
	ok = 0;
	while(i < NUM_PARAMS){
		if(strncmp(g, config[i].attrib, 512)==0){
			switch(config[i].type){
				case 0: strncpy(config[i].valeur.string, d, 1024); break;
				case 1: config[i].valeur.integer = convert_int(d); break;
				case 2: config[i].valeur.integer = convert_boolean(d); break;
			}
			ok = 1;
			break;
		}
		i++;
	}
	if(ok == 0){
		fprintf(stderr, "%s %i: erreur dans le fichier de config a la ligne \"%s\": parametre innexistant\n", __FILE__, __LINE__, buf);
		exit(1);
	}
}

int convert_int(char *buf){
	int res = 0;
	int count = 1;
	while(*buf != 0){
		res *= 10;
		res += *buf-48;
		count *= 10;
		buf++;
	}	
	return res;
}

int convert_boolean(char *buf){
	char *src;
	src = buf;
	*src = lowercase(*src);
	switch(*src){
		case 'o': return(TRUE);
		case 't': return(TRUE);
		case 'y': return(TRUE);

		case 'n': return(FALSE);
		case 'f': return(FALSE);
	}
	return(FALSE);
}

char lowercase(char in){
	if(in > 64 && in < 91)in+=32;
	return in;
}

void miseenforme(char *params){
	char *src;
	char *dst;
	char *fin;
	char *mem;
	int protection;
	int debut;
	int space;

        /* suppression des commentaires */
	src = params;
	protection = 0;
	while(*src != 0){
		if(*src == '"'){
			protection ^= 0xff;
			src++;
			continue;
		}
		if(protection != 0xff && *src == '#'){
			*src=0;
			break;
		}
		src++;
	}

	/* suppression des espaces inutiles */
	debut = 0;
	space = 0;	
	src = params;
	dst = params;
	protection = 0;
	while(*src != 0){
		/* on conserve l'interieur des guillemets sans modifs */
		if(*src == '"' || protection == 0xff){
			*dst = *src;
			if(*src == '"'){
				protection ^= 0xff; /* ou  exclusif, inversion de octets pour le flag*/
			}
			src++;
			dst++;
			continue;
		}

		/* on ignore les saut de lignes */
		if(*src == '\n' || *src == '\r'){
			src++;
			continue;
		}

		/* si on a un caracteres non blanc on le recopie */
		if(!(*src == ' ' || *src == '\t')){
			debut = 1;
			*dst = *src;
			dst++;
			src++;
			space = 0;
			continue;
		}

		/* dans les autres cas, on considere que c'est un espace, si ce n'est pas le premier, on met un espace */
		if(space == 0 && debut == 1){
			*dst=' ';
			dst++;
		}
		space = 1;
		src++;
	}
	*dst=0;
	fin = dst;

	/* suppresion de l'eventuel dernier espace */
	if(*(fin-1)==' '){
		fin--;
		dst--;
		*fin=0;
	}

	/* mise en forme des egales colles: peuvent etre mot=mot */
	src = params;
	protection = 0;
	while(*src != 0){
		if(*src == '"'){
			protection ^= 0xff;
			src++;
			continue;
		}
		if(protection != 255 && *src == '=')break;
		src++;
	}
	if(*src == '='){
		mem = src;
		if(*(src+1)!=' ')fin++;
		if(*(src-1)!=' '){fin++; src++;}

		*(fin+1)=0;
		while(fin!=mem){
			*fin=*dst;
			fin--;
			dst--;
		}

		*src = '=';
		*(src-1) = ' ';
		*(src+1) = ' ';
	}
}

