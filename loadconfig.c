/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: loadconfig.c 124 2006-05-10 21:46:12Z thierry $
 *
 */

#include "config.h"

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>

#include "arpalert.h"
#include "loadconfig.h"
#include "log.h"

#define OPTIONS "f:i:p:Pe:dwD:l:v"

char msg[4096];
int dump = 0;

void miseenforme(char*);
void miseenmemoire(char*);
void to_lower(char *);
char lowercase(char);
int convert_octal(char*);
int convert_int(char*);
int convert_boolean(char*);

void usage(){
	printf(
	"\n"
	"arpalert [-f config_file] [-i network_interface] [-p pid_file] [-e exec_script]\n"
	"    [-D log_level] [-l leases_file] [-d][-v][-h][-w][-v][-P]\n"
	"\n"
	"    -d run as daemon\n"
	"    -v dump config\n"
	"    -h this help\n"
	"    -w debug option: print a dump of paquets captured\n"
	"    -P run in promiscuous mode\n"
	"\n");
	exit(1);
}

void config_load(int argc, char *argv[]){
	FILE *fp;
	char buffer[4096];
	char *buf;
	int i;

	/* loading default values */
	config[CF_MACLIST].type = 0;
	strncpy(config[CF_MACLIST].attrib, "maclist file", ATTRIB_LEN);
	config[CF_MACLIST].valeur.string[0] = 0;
	
	config[CF_LOGFILE].type = 0;
	strncpy(config[CF_LOGFILE].attrib, "log file", ATTRIB_LEN);
	config[CF_LOGFILE].valeur.string[0] = 0, "";
	
	config[CF_ACTION].type = 0;
	strncpy(config[CF_ACTION].attrib, "action on detect", ATTRIB_LEN);
	config[CF_ACTION].valeur.string[0] = 0;
	
	config[CF_LOCKFILE].type = 0;
	strncpy(config[CF_LOCKFILE].attrib, "lock file", ATTRIB_LEN);
	strncpy(config[CF_LOCKFILE].valeur.string, PID_FILE, STRVAL_LEN);
	
	config[CF_DAEMON].type = 2;
	strncpy(config[CF_DAEMON].attrib, "daemon", ATTRIB_LEN);
	config[CF_DAEMON].valeur.integer = FALSE;
	
	config[CF_RELOAD].type = 1;
	strncpy(config[CF_RELOAD].attrib, "reload interval", ATTRIB_LEN);
	config[CF_RELOAD].valeur.integer = 600;
	
	config[CF_LOGLEVEL].type = 1;
	strncpy(config[CF_LOGLEVEL].attrib, "log level", ATTRIB_LEN);
	config[CF_LOGLEVEL].valeur.integer = 6;
	
	config[CF_USESYSLOG].type = 2;
	strncpy(config[CF_USESYSLOG].attrib, "use syslog", ATTRIB_LEN);
	config[CF_USESYSLOG].valeur.integer = TRUE;
	
	config[CF_TIMEOUT].type = 1;
	strncpy(config[CF_TIMEOUT].attrib, "execution timeout", ATTRIB_LEN);
	config[CF_TIMEOUT].valeur.integer = 10;

	config[CF_MAXTH].type = 1;
	strncpy(config[CF_MAXTH].attrib, "max alert", ATTRIB_LEN);
	config[CF_MAXTH].valeur.integer = 20;

	config[CF_BLACKLST].type = 0;
	strncpy(config[CF_BLACKLST].attrib, "maclist alert file", ATTRIB_LEN);
	config[CF_BLACKLST].valeur.string[0] = 0;
	
	config[CF_LEASES].type = 0;
	strncpy(config[CF_LEASES].attrib, "maclist leases file", ATTRIB_LEN);
	config[CF_LEASES].valeur.string[0] = 0;
	
	config[CF_IF].type = 0;
	strncpy(config[CF_IF].attrib, "interface", ATTRIB_LEN);
	config[CF_IF].valeur.string[0] = 0;

	config[CF_ABUS].type = 1;
	strncpy(config[CF_ABUS].attrib, "max request", ATTRIB_LEN);
	config[CF_ABUS].valeur.integer = 1000000;
	
	config[CF_MAXENTRY].type = 1;
	strncpy(config[CF_MAXENTRY].attrib, "max entry", ATTRIB_LEN);
	config[CF_MAXENTRY].valeur.integer = 1048576;	/* 14Mo */
	
	config[CF_DMPWL].type = 2;
	strncpy(config[CF_DMPWL].attrib, "dump white list", ATTRIB_LEN);
	config[CF_DMPWL].valeur.integer = FALSE;
			
	config[CF_DMPBL].type = 2;
	strncpy(config[CF_DMPBL].attrib, "dump black list", ATTRIB_LEN);
	config[CF_DMPBL].valeur.integer = FALSE;
		
	config[CF_DMPAPP].type = 2;
	strncpy(config[CF_DMPAPP].attrib, "dump new address", ATTRIB_LEN);
	config[CF_DMPAPP].valeur.integer = TRUE;
	
	config[CF_TOOOLD].type = 1;
	strncpy(config[CF_TOOOLD].attrib, "mac timeout", ATTRIB_LEN);
	config[CF_TOOOLD].valeur.integer = 2592000; /* 1 month */

	config[CF_LOGALLOW].type = 2;
	strncpy(config[CF_LOGALLOW].attrib, "log referenced address", ATTRIB_LEN);
	config[CF_LOGALLOW].valeur.integer = FALSE;
	
	config[CF_ALRALLOW].type = 2;
	strncpy(config[CF_ALRALLOW].attrib, "alert on referenced address", ATTRIB_LEN);
	config[CF_ALRALLOW].valeur.integer = FALSE;
	
	config[CF_LOGDENY].type = 2;
	strncpy(config[CF_LOGDENY].attrib, "log deny address", ATTRIB_LEN);
	config[CF_LOGDENY].valeur.integer = TRUE;
	
	config[CF_ALRDENY].type = 2;
	strncpy(config[CF_ALRDENY].attrib, "alert on deny address", ATTRIB_LEN);
	config[CF_ALRDENY].valeur.integer = TRUE;

	config[CF_LOGNEW].type = 2;
	strncpy(config[CF_LOGNEW].attrib, "log new address", ATTRIB_LEN);
	config[CF_LOGNEW].valeur.integer = TRUE;

	config[CF_ALRNEW].type = 2;
	strncpy(config[CF_ALRNEW].attrib, "alert on new address", ATTRIB_LEN);
	config[CF_ALRNEW].valeur.integer = TRUE;

	config[CF_LOGNEWMAC].type = 2;
	strncpy(config[CF_LOGNEWMAC].attrib, "log new mac address", ATTRIB_LEN);
	config[CF_LOGNEWMAC].valeur.integer = TRUE;

	config[CF_ALRNEWMAC].type = 2;
	strncpy(config[CF_ALRNEWMAC].attrib, "alert on new mac address", ATTRIB_LEN);
	config[CF_ALRNEWMAC].valeur.integer = TRUE;

	config[CF_ALRIP].type = 2;
	strncpy(config[CF_ALRIP].attrib, "alert on ip change", ATTRIB_LEN);
	config[CF_ALRIP].valeur.integer = TRUE;

	config[CF_LOGIP].type = 2;
	strncpy(config[CF_LOGIP].attrib, "log ip change", ATTRIB_LEN);
	config[CF_LOGIP].valeur.integer = TRUE;

	config[CF_AUTHFILE].type = 0;
	strncpy(config[CF_AUTHFILE].attrib, "auth request file", ATTRIB_LEN);
	config[CF_AUTHFILE].valeur.string[0] = 0;

	config[CF_LOG_UNAUTH_RQ].type = 2;
	strncpy(config[CF_LOG_UNAUTH_RQ].attrib, "log unauth request", ATTRIB_LEN);
	config[CF_LOG_UNAUTH_RQ].valeur.integer = TRUE;

	config[CF_ALERT_UNAUTH_RQ].type = 2;
	strncpy(config[CF_ALERT_UNAUTH_RQ].attrib, "alert on unauth request", ATTRIB_LEN);
	config[CF_ALERT_UNAUTH_RQ].valeur.integer = TRUE;

	config[CF_UNAUTH_TO_METHOD].type = 1;
	strncpy(config[CF_UNAUTH_TO_METHOD].attrib, "unauth ignore time method", ATTRIB_LEN);
	config[CF_UNAUTH_TO_METHOD].valeur.integer = 2;
	
	config[CF_LOG_ABUS].type = 2;
	strncpy(config[CF_LOG_ABUS].attrib, "log request abus", ATTRIB_LEN);
	config[CF_LOG_ABUS].valeur.integer = TRUE;

	config[CF_ALERT_ABUS].type = 2;
	strncpy(config[CF_ALERT_ABUS].attrib, "alert on request abus", ATTRIB_LEN);
	config[CF_ALERT_ABUS].valeur.integer = TRUE;

	config[CF_LOG_BOGON].type = 2;
	strncpy(config[CF_LOG_BOGON].attrib, "log mac error", ATTRIB_LEN);
	config[CF_LOG_BOGON].valeur.integer = TRUE;

	config[CF_ALR_BOGON].type = 2;
	strncpy(config[CF_ALR_BOGON].attrib, "alert on mac error", ATTRIB_LEN);
	config[CF_ALR_BOGON].valeur.integer = TRUE;

	config[CF_IGNORE_UNKNOWN].type = 2;
	strncpy(config[CF_IGNORE_UNKNOWN].attrib, "ignore unknown sender", ATTRIB_LEN);
	config[CF_IGNORE_UNKNOWN].valeur.integer = TRUE;

	config[CF_DUMP_PAQUET].type = 2;
	strncpy(config[CF_DUMP_PAQUET].attrib, "dump paquet", ATTRIB_LEN);
	config[CF_DUMP_PAQUET].valeur.integer = FALSE;

	config[CF_PROMISC].type = 2;
	strncpy(config[CF_PROMISC].attrib, "promiscuous", ATTRIB_LEN);
	config[CF_PROMISC].valeur.integer = FALSE;

	config[CF_ANTIFLOOD_INTER].type = 1;
	strncpy(config[CF_ANTIFLOOD_INTER].attrib, "anti flood interval", ATTRIB_LEN);
	config[CF_ANTIFLOOD_INTER].valeur.integer = 10; /* 10 secondes */
	
	config[CF_ANTIFLOOD_GLOBAL].type = 1;
	strncpy(config[CF_ANTIFLOOD_GLOBAL].attrib, "anti flood global", ATTRIB_LEN);
	config[CF_ANTIFLOOD_GLOBAL].valeur.integer = 50; /* 50 secondes */

	config[CF_LOG_FLOOD].type = 2;
	strncpy(config[CF_LOG_FLOOD].attrib, "log flood", ATTRIB_LEN);
	config[CF_LOG_FLOOD].valeur.integer = TRUE;

	config[CF_ALERT_ON_FLOOD].type = 2;
	strncpy(config[CF_ALERT_ON_FLOOD].attrib, "alert on flood", ATTRIB_LEN);
	config[CF_ALERT_ON_FLOOD].valeur.integer = TRUE;
	
	config[CF_IGNORE_ME].type = 2;
	strncpy(config[CF_IGNORE_ME].attrib, "ignore me", ATTRIB_LEN);
	config[CF_IGNORE_ME].valeur.integer = TRUE;
	
	config[CF_UMASK].type = 3;
	strncpy(config[CF_UMASK].attrib, "umask", ATTRIB_LEN);
	config[CF_UMASK].valeur.integer = 0133;

	config[CF_USER].type = 0;
	strncpy(config[CF_USER].attrib, "user", ATTRIB_LEN);
	config[CF_USER].valeur.string[0] = 0;

	config[CF_CHROOT].type = 0;
	strncpy(config[CF_CHROOT].attrib, "chroot dir", ATTRIB_LEN);
	config[CF_CHROOT].valeur.string[0] = 0;

	config[CF_IGNORESELFTEST].type = 2;
	strncpy(config[CF_IGNORESELFTEST].attrib, "ignore self test", ATTRIB_LEN);
	config[CF_IGNORESELFTEST].valeur.integer = TRUE;

	config[CF_ALERT_MACCHG].type = 2;
	strncpy(config[CF_ALERT_MACCHG].attrib, "alert on mac change", ATTRIB_LEN);
	config[CF_ALERT_MACCHG].valeur.integer = TRUE; 

	config[CF_LOG_MACCHG].type = 2;
	strncpy(config[CF_LOG_MACCHG].attrib, "log mac change", ATTRIB_LEN);
	config[CF_LOG_MACCHG].valeur.integer = TRUE; 
							

	// load command line parameters for config file
	strncpy(config_file, CONFIG_FILE, CONFIGFILE_LEN);
	for(i=1; i<argc; i++){
		if(argv[i][0]=='-' && argv[i][1]=='h'){
			usage();
		}
		if(argv[i][0]=='-' && argv[i][1]=='f'){
			if(i+1 >= argc){
				fprintf(stderr, "Option -f without argument\n");
				usage();
			}
			i++;
			strncpy(config_file, argv[i], CONFIGFILE_LEN);
		}
	}

	// load config file values
	buf = buffer;
	fp = fopen(config_file, "r");
	if(fp == NULL){
		fprintf(stderr, "[%s %i] didn't find %s, loading default config\n",
			__FILE__, __LINE__, config_file);
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
				case 'f':
					i++;
					break;

				case 'i':
					if(i+1 >= argc){
						fprintf(stderr, "Option -i without argument\n");
						usage();
					}
					i++;
					strncpy(config[CF_IF].valeur.string, argv[i], STRVAL_LEN);
					break;
	
				case 'p':
					if(i+1 >= argc){
						fprintf(stderr, "Option -p without argument\n");
						usage();
					}
					i++;
					strncpy(config[CF_LOCKFILE].valeur.string, argv[i], STRVAL_LEN);
					break;
	
				case 'e':
					if(i+1 >= argc){
						fprintf(stderr, "Option -e without argument\n");
						usage();
					}
					i++;
					strncpy(config[CF_ACTION].valeur.string, argv[i], STRVAL_LEN);
					break;
				
				case 'D':
					if(i+1 >= argc){
						fprintf(stderr, "Option -D without argument\n");
						usage();
					}
					i++;
					if(argv[i][0] < 48 || argv[i][0] > 55){
						fprintf(stderr, "Wrong -D parameter\n");
						usage();
					}
					config[CF_LOGLEVEL].valeur.integer = argv[i][0] - 48;
					break;
	
				case 'l':
					if(i+1 >= argc){
						fprintf(stderr, "Option -l without argument\n");
						usage();
					}
					i++;
					strncpy(config[CF_LEASES].valeur.string, argv[i], STRVAL_LEN);
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
					fprintf(stderr, "Wrong option: -%c\n", argv[i][1]);
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
		if(strncmp(g, config[i].attrib, ATTRIB_LEN)==0){
			switch(config[i].type){
				case 0: strncpy(config[i].valeur.string, d, STRVAL_LEN); break;
				case 1: config[i].valeur.integer = convert_int(d); break;
				case 2: config[i].valeur.integer = convert_boolean(d); break;
				case 3: config[i].valeur.integer = convert_octal(d); break;
			}
			ok = 1;
			break;
		}
		i++;
	}
	if(ok == 0){
		fprintf(stderr, "[%s %i] error in config file at "
		        "line: \"%s\": parameter inexistent\n",
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
			fprintf(stderr, "[%s %i] error in config file in "
			        "string \"%s\": octal value expected\n",
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
			fprintf(stderr, "[%s %i] error in config file in "
			        "string \"%s\": integer value expected\n",
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
	to_lower(buf);

	if(strcmp("oui",   buf) == 0) return(TRUE);
	if(strcmp("yes",   buf) == 0) return(TRUE);
	if(strcmp("true",  buf) == 0) return(TRUE);
	if(strcmp("1",     buf) == 0) return(TRUE);
	
	if(strcmp("non",   buf) == 0) return(FALSE);
	if(strcmp("no",    buf) == 0) return(FALSE);
	if(strcmp("false", buf) == 0) return(FALSE);
	if(strcmp("0",     buf) == 0) return(FALSE);

	fprintf(stderr, "[%s %i] error in config file: boolean value expected\n",
		__FILE__, __LINE__);
	exit(1);	 
}

void to_lower(char *in){
	while(*in != 0){
		if(*in > 64 && *in < 91)*in+=32;
		in++;
	}
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

	// delete comments
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

	// delete unused blank characters
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
				protection = 0x00; 
			}
			src++;
			dst++;
			continue;
		}

		// ignore end line character
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

		*(src-1) = ' ';
		*src     = '=';
		*(src+1) = ' ';
	}
}

