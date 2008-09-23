#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include "loadconfig.h"
#include "log.h"

#define OPTIONS "f:i:p:Pe:dwD:l:v"

char msg[4096];
int dump = 0;

void miseenforme(char*);
void miseenmemoire(char*);
char lowercase(char);
int convert_octal(char*);
int convert_int(char*);
int convert_boolean(char*);

void usage(){
	printf(
	"\n"
	"arpalert [-f config_file] [-i network_interface] [-p pid_file] [-e exec_script]\n"
	"    [-D log_level] [-l leases_file] [-d][-v][-h][-w]\n"
	"\n"
	"    -d run as daemon\n"
	"    -v dump config\n"
	"    -h this help\n"
	"    -w debug option: print a dump of paquets captured\n"
	"\n");
	exit(1);
}

void config_load(int argc, char *argv[]){
	FILE *fp;
	char buffer[4096];
	char *buf;
	char msgd[512];
	int i;

	/* loading default values */
	config[CF_MACLIST].type = 0;
	strncpy(config[CF_MACLIST].attrib, "maclist file", 512);
	config[CF_MACLIST].valeur.string[0] = 0;
	
	config[CF_LOGFILE].type = 0;
	strncpy(config[CF_LOGFILE].attrib, "log file", 512);
	config[CF_LOGFILE].valeur.string[0] = 0, "";
	
	config[CF_ACTION].type = 0;
	strncpy(config[CF_ACTION].attrib, "action on detect", 512);
	config[CF_ACTION].valeur.string[0] = 0;
	
	config[CF_LOCKFILE].type = 0;
	strncpy(config[CF_LOCKFILE].attrib, "lock file", 512);
	strncpy(config[CF_LOCKFILE].valeur.string, PID_FILE, 1024);
	
	config[CF_DAEMON].type = 2;
	strncpy(config[CF_DAEMON].attrib, "daemon", 512);
	config[CF_DAEMON].valeur.integer = FALSE;
	
	config[CF_RELOAD].type = 1;
	strncpy(config[CF_RELOAD].attrib, "reload interval", 512);
	config[CF_RELOAD].valeur.integer = 600;
	
	config[CF_LOGLEVEL].type = 1;
	strncpy(config[CF_LOGLEVEL].attrib, "log level", 512);
	config[CF_LOGLEVEL].valeur.integer = 6;
	
	config[CF_USESYSLOG].type = 2;
	strncpy(config[CF_USESYSLOG].attrib, "use syslog", 512);
	config[CF_USESYSLOG].valeur.integer = TRUE;
	
	config[CF_TIMEOUT].type = 1;
	strncpy(config[CF_TIMEOUT].attrib, "execution timeout", 512);
	config[CF_TIMEOUT].valeur.integer = 10;

	config[CF_MAXTH].type = 1;
	strncpy(config[CF_MAXTH].attrib, "max alert", 512);
	config[CF_MAXTH].valeur.integer = 20;

	config[CF_BLACKLST].type = 0;
	strncpy(config[CF_BLACKLST].attrib, "maclist alert file", 512);
	config[CF_BLACKLST].valeur.string[0] = 0;
	
	config[CF_LEASES].type = 0;
	strncpy(config[CF_LEASES].attrib, "maclist leases file", 512);
	config[CF_LEASES].valeur.string[0] = 0;
	
	config[CF_IF].type = 0;
	strncpy(config[CF_IF].attrib, "interface", 512);
	config[CF_IF].valeur.string[0] = 0;

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
	config[CF_TOOOLD].valeur.integer = 2592000; /* 1 month */

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
	strncpy(config[CF_IGNORE_UNKNOW].attrib, "ignore unknown sender", 512);
	config[CF_IGNORE_UNKNOW].valeur.integer = TRUE;

	config[CF_DUMP_PAQUET].type = 2;
	strncpy(config[CF_DUMP_PAQUET].attrib, "dump paquet", 512);
	config[CF_DUMP_PAQUET].valeur.integer = FALSE;

	config[CF_PROMISC].type = 2;
	strncpy(config[CF_PROMISC].attrib, "promiscuous", 512);
	config[CF_PROMISC].valeur.integer = FALSE;

	config[CF_ANTIFLOOD_INTER].type = 1;
	strncpy(config[CF_ANTIFLOOD_INTER].attrib, "anti flood interval", 512);
	config[CF_ANTIFLOOD_INTER].valeur.integer = 10; /* 10 secondes */
	
	config[CF_ANTIFLOOD_GLOBAL].type = 1;
	strncpy(config[CF_ANTIFLOOD_GLOBAL].attrib, "anti flood global", 512);
	config[CF_ANTIFLOOD_GLOBAL].valeur.integer = 50; /* 50 secondes */

	config[CF_LOG_FLOOD].type = 2;
	strncpy(config[CF_LOG_FLOOD].attrib, "log flood", 512);
	config[CF_LOG_FLOOD].valeur.integer = TRUE;

	config[CF_ALERT_ON_FLOOD].type = 2;
	strncpy(config[CF_ALERT_ON_FLOOD].attrib, "alert on flood", 512);
	config[CF_ALERT_ON_FLOOD].valeur.integer = TRUE;
	
	config[CF_IGNORE_ME].type = 2;
	strncpy(config[CF_IGNORE_ME].attrib, "ignore me", 512);
	config[CF_IGNORE_ME].valeur.integer = TRUE;
	
	config[CF_UMASK].type = 4;
	strncpy(config[CF_UMASK].attrib, "umask", 512);
	config[CF_UMASK].valeur.integer = 0133;

	config[CF_USER].type = 0;
	strncpy(config[CF_USER].attrib, "user", 512);
	config[CF_USER].valeur.string[0] = 0;

	config[CF_CHROOT].type = 0;
	strncpy(config[CF_CHROOT].attrib, "chroot dir", 512);
	config[CF_CHROOT].valeur.string[0] = 0;

	config[CF_IGNORESELFTEST].type = 2;
	strncpy(config[CF_IGNORESELFTEST].attrib, "ignore self test", 512);
	config[CF_IGNORESELFTEST].valeur.integer = FALSE;
	
	/* load command line parameters for config file */
	strncpy(config_file, CONFIG_FILE, 2048);
	for(i=1; i<argc; i++){
		if(argv[i][0]=='-' && argv[i][1]=='f'){
		       	if(i+1 >= argc)usage();
			i++;
			strncpy(config_file, argv[i], 2048);
		}
	}

	buf = buffer;
	fp = fopen(config_file, "r");
	if(fp == NULL){
		snprintf(msgd, 512, "[%s %i] don't found %s, loading default config\n",
			__FILE__, __LINE__, config_file);
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

	/* load command line parameters 
	 * (this supplant config file params) */
	for(i=1; i<argc; i++){
		if(argv[i][0]=='-'){
			switch(argv[i][1]){
				case 'i':
					if(i+1 >= argc)usage();
					i++;
					strncpy(config[CF_IF].valeur.string, argv[i], 1024);
					break;
	
				case 'p':
					if(i+1 >= argc)usage();
					i++;
					strncpy(config[CF_LOCKFILE].valeur.string, argv[i], 1024);
					break;
	
				case 'e':
					if(i+1 >= argc)usage();
					i++;
					strncpy(config[CF_ACTION].valeur.string, argv[i], 1024);
					break;
				
				case 'D':
					if(i+1 >= argc)usage();
					i++;
					if(argv[i][0] < 48 || argv[i][0] > 55){
						fprintf(stderr, "Wrong -D parameter");
						usage();
					}
					config[CF_LOGLEVEL].valeur.integer = argv[i][0] - 48;
					break;
	
				case 'l':
					if(i+1 >= argc)usage();
					i++;
					strncpy(config[CF_LEASES].valeur.string, argv[i], 1024);
					break;
	
				case 'v':
					dump = 1;
					break;
				
				case 'w':
					config[CF_DUMP_PAQUET].valeur.integer = TRUE;
					break;
				
				case 'd':
					config[CF_DAEMON].valeur.integer = TRUE;
					break;
	
				case 'P':
					config[CF_PROMISC].valeur.integer = TRUE;
					break;
					
				case 'h':
				case '?':
				default:
					usage();
					exit(1);
					break;
			}
		}
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
						printf("%s = true\n", config[i].attrib);
					} else {
						printf("%s = false\n", config[i].attrib);
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
		fprintf(stderr, "%i: error in config file at line: %s\n", __LINE__, buf);
		exit(1);
	}
	if(*(m_eq-1)!=' '){
		fprintf(stderr, "%i: error in config file at line: %s\n", __LINE__, buf);
		exit(1);
	}
	if(*(m_eq+1)!=' '){
		fprintf(stderr, "%i: error in config file at line: %s\n", __LINE__, buf);
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
				case 4: config[i].valeur.integer = convert_octal(d); break;
			}
			ok = 1;
			break;
		}
		i++;
	}
	if(ok == 0){
		fprintf(stderr, "%s %i: error in config file at line: \"%s\": parametre innexistant\n",
			__FILE__, __LINE__, buf);
		exit(1);
	}
}

int convert_octal(char *buf){
	int res = 0;
	char *b;
	
	int i;

	b = buf;
	while(*buf != 0){
		if(*buf<'0' || *buf>'7'){
			fprintf(stderr, "%s %i: error in config file in string \"%s\": octal value expected\n",
				__FILE__, __LINE__, b);
			exit(1);
		}
		i = res;
		res *= 8;
		res += *buf - 48;
		buf++;
	}
	return res;
}

int convert_int(char *buf){
	int res = 0;
	char *b;

	b = buf;
	while(*buf != 0){
		if(*buf<'0' || *buf>'9'){
			fprintf(stderr, "%s %i: error in config file in string \"%s\": integer value expected\n",
				__FILE__, __LINE__, b);
			exit(1);
		}
		res *= 10;
		res += *buf - 48;
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
		case '1': return(TRUE);

		case 'n': return(FALSE);
		case 'f': return(FALSE);
		case '0': return(FALSE);
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

		/* dans les autres cas, on considere que c'est un espace,
		 * si ce n'est pas le premier, on met un espace */
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

