#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "data.h"
#include "sens.h"
#include "log.h"
#include "config.h"
#include "loadconfig.h"

/* Taille de la table de hachage (nombre premier) */
#define HASH_SIZE 1999

/* debug: */
#define DEBUG_SENS 1

/* structures */
struct pqt {
	data_ip ip_s;
	data_ip ip_d;
	struct pqt *next;
};

/* hash */ 
struct pqt *pqt_h[HASH_SIZE];

unsigned int sens_hash(data_ip, data_ip);

/* data_init */
void sens_init(void) {
	char buffer[8192];
	char *buf;
	FILE *fp;
	int i, dec, line;
	unsigned char ip[16];
	data_ip ip_s;
	data_ip ip_d;
	
	memset(&pqt_h, 0, HASH_SIZE * sizeof(struct pqt *));

	if(config[CF_AUTHFILE].valeur.string[0]==0)return;

	fp = fopen(config[CF_AUTHFILE].valeur.string, "r");
	if(fp == NULL){
		logmsg(LOG_ERR, "[%s %i] don't found file %s", __FILE__, __LINE__,
			config[CF_AUTHFILE].valeur.string);
		return;
	}
	
	buf = buffer;
	line = 0;
	
	while((buf = fgets(buf, 8192, fp)) != NULL){
		line++;
		
		/* mise en forme 
		 * replace les separateurs par un blanc unique
		 */
		if(buf[0]=='#')continue;

		/* suppressiopn des caracteres blancs */
		i=0;
		dec=0;
		while(buf[i]!=0 && i<8192){
			if(buf[i]=='\n'||buf[i]=='\r'){
				buf[dec]=0;
				break;
			}

			if(buf[i]==' '||buf[i]=='\t'){
				i++;		
			}else{
				buf[dec] = buf[i];
				dec++;
				i++;
			}
		}
		if(i<8192)buf[i]=0;
		
		/* extraction des ips */
		i=0;
		dec=0;
		memset(ip, 0, 16);
		while(1){
			if((buf[i]>='0' && buf[i]<='9')||buf[i]=='.'){
				ip[dec]=buf[i];
				if(dec>15){
					logmsg(LOG_ERR, 
						"[%s %i] invalid ip address [%s] at line [%s:%d]", 
						__FILE__, __LINE__, 
						ip, config[CF_AUTHFILE].valeur.string, line);
					exit(1);
				}
				dec++;
			}
			if(buf[i]==':'){
				ip_s.ip=data_toip(ip);
				#ifdef DEBUG
				logmsg(LOG_DEBUG, "[%s %i] ip address [%s] source",
					__FILE__, __LINE__, ip);
				#endif
				dec=0;
				memset(ip, 0, 16);
			}
			if(buf[i]==',' || buf[i]==0){
				ip_d.ip=data_toip(ip);
				sens_add(ip_s, ip_d);
				#ifdef DEBUG
				logmsg(LOG_DEBUG, "[%s %i] ip address [%s] dest",
					__FILE__, __LINE__, ip);
				#endif
				dec=0;
				memset(ip, 0, 16);
			}
			if(buf[i]==0||i>=8192)break;
			i++;
		}
	}
	fclose(fp);
}

/* data_add */
void sens_add(data_ip ipa, data_ip ipb){
	int h;
	struct pqt *spqt;
	struct pqt *mpqt;

	mpqt = (struct pqt *)malloc(sizeof(struct pqt));
	mpqt->ip_s=ipa;
	mpqt->ip_d=ipb;
	mpqt->next=NULL;

	h = sens_hash(ipa, ipb);
	spqt = (struct pqt *)pqt_h[h];
	
	/* find a free space */
	if(spqt==NULL){
		pqt_h[h]=(struct pqt *)mpqt;
	} else {
		while(spqt->next != NULL)spqt=spqt->next;
		spqt->next = mpqt;
	}
}

void sens_free(void){
	int i;
	struct pqt *mpqt;
	struct pqt *spqt;
	
	for(i=0; i<HASH_SIZE; i++){
		spqt=pqt_h[i];
		while(spqt != NULL){
			mpqt=spqt;
			spqt=spqt->next;
			free(mpqt);
		}
	}
}

int sens_exist(data_ip ipa, data_ip ipb){
		int h;
		struct pqt *spqt;

		h = sens_hash(ipa, ipb);
		spqt = (struct pqt *)pqt_h[h];
		if(spqt==NULL)return(FALSE);
		while(spqt != NULL){
			if(spqt->ip_s.ip==ipa.ip && spqt->ip_d.ip==ipb.ip)return(TRUE);
			spqt=spqt->next;
		}
		return(FALSE);
}

/* fait le hachage */
unsigned int sens_hash(data_ip ipa, data_ip ipb){
	unsigned int v;

	v = (ipa.ip + ipb.ip) % HASH_SIZE;
	return(v);
}


