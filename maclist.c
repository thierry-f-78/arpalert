#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "config.h"
#include "maclist.h"
#include "data.h"
#include "loadconfig.h"
#include "log.h"

time_t lastlog;

void maclist_file(char *, int);

void maclist_load(void){
	if(config[CF_MACLIST].valeur.string[0] != 0){
		maclist_file(config[CF_MACLIST].valeur.string, ALLOW);
	}

	if(config[CF_BLACKLST].valeur.string[0] != 0){
		maclist_file(config[CF_BLACKLST].valeur.string, DENY);
	}
}

void maclist_file(char *file, int level){
	FILE *fp;	/* pointeur du fichier */
	char buf;	/* pointeur sur la ligne lue */
	unsigned char key[17];
	unsigned char ip[15];
	int ip_32;
	int qui;
	int p, ligne, car;
	data_mac mac;

	memset(key, 0, 17);
	memset(ip, 0, 15);
	
	/* ouvrir le fichier */
	fp = fopen(file, "r");
	if(fp == NULL){
		logmsg(LOG_ERR, "[%s %i] Don't found file [%s]", __FILE__, __LINE__, file);
		exit(1);
	}

	qui = 1;
	p = 0;
	ligne = 1;
	car = 0;
	while((buf=fgetc(fp))!=EOF){
		car ++;
		
		/* caractere blanc, on ignore, on change de champ */
		if(buf==' ' || buf=='\t'){
			qui=2;
			key[p]=0;
			p=0;
			continue;
		}
	
		if(buf=='\n'){
			data_tohex(key, &mac);
			ip_32 = data_toip(ip);
			data_add(&mac, level, ip_32);
			
			for(p=0; p<14; p++)ip[p]=0;
			p=0;
			qui=1;
			car=0;
			ligne++;
			memset(key, 0, 17);
			memset(ip, 0, 15);
			continue;
		}


		/* copie les données si elle sont consideres comme @ mac */
		if(qui==1){
			if(p>=17){
				logmsg(LOG_ERR, "[%s %i] Mac address format error at line %i character %i", __FILE__, __LINE__, ligne, car);
				exit(1);
			}
			key[p]=buf;
			p++;
			continue;
		}
		
		/* copie les données considérées comme ip */
		if(qui==2){
			if(p>=15){
				logmsg(LOG_ERR, "[%s %i] IP address error at line %i character %i", __FILE__, __LINE__, ligne, car);
				exit(1);
			}
			if(( buf >= 48 && buf <= 57 ) || buf == 46){
				#ifdef DEBUG
				logmsg(LOG_DEBUG, "[%s %i] ip[%i] = %c", __FILE__, __LINE__, p, buf);
				#endif
				ip[p]=buf;
				p++;
				continue;
			} else {
				logmsg(LOG_ERR, "[%s %i] IP Address format error at line %i character %i near %c", __FILE__, __LINE__, ligne, car, buf);
				exit(1);
			}
		}
		
	}
	fclose(fp);
}

void maclist_reload(void){
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Reload maclist", __FILE__, __LINE__);
	#endif
	data_reset();
	maclist_load();
}
