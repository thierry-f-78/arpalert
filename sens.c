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
	data_mac mac;
	data_ip ip_d;
	struct pqt *next;
};

/* hash */ 
struct pqt *pqt_h[HASH_SIZE];

unsigned int sens_hash(data_mac *, data_ip);

/* data_init */
void sens_init(void) {
	char buffer[8192];
	char *buf;
	FILE *fp;
	int i, dec, line;
	unsigned char ip[32];
	data_mac mac;
	data_ip ip_d;
	
	memset(&pqt_h, 0, HASH_SIZE * sizeof(struct pqt *));

	if(config[CF_AUTHFILE].valeur.string[0]==0)return;

	fp = fopen(config[CF_AUTHFILE].valeur.string, "r");
	if(fp == NULL){
		logmsg(LOG_ERR, "[%s %i] don't found file %s", __FILE__, __LINE__,
			config[CF_AUTHFILE].valeur.string);
		exit(1);
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
			if((buf[i]>='0' && buf[i]<='9') || \
			  (buf[i]>='a' && buf[i]<='f') || \
			  (buf[i]>='A' && buf[i]<='F') || \
			  buf[i]=='.' || buf[i]==':'){
				ip[dec]=buf[i];
				if(dec>17){
					logmsg(LOG_ERR, 
						"[%s %i] invalid ip address [%s] at line [%s:%d]", 
						__FILE__, __LINE__, 
						ip, config[CF_AUTHFILE].valeur.string, line);
					exit(1);
				}
				dec++;
			}
			if(buf[i]=='-'){
				data_tohex(ip, &mac);
				#ifdef DEBUG_SENS
				logmsg(LOG_DEBUG, "[%s %i] mac address [%s] source",
					__FILE__, __LINE__, ip);
				#endif
				dec=0;
				memset(ip, 0, 32);
			}
			if(buf[i]==',' || buf[i]==0){
				ip_d.ip=data_toip(ip);
				sens_add(&mac, ip_d);
				#ifdef DEBUG_SENS
				logmsg(LOG_DEBUG, "[%s %i] ip address [%s] dest",
					__FILE__, __LINE__, ip);
				#endif
				dec=0;
				memset(ip, 0, 32);
			}
			if(buf[i]==0||i>=8192)break;
			i++;
		}
	}
	fclose(fp);
}

/* data_add */
void sens_add(data_mac *mac, data_ip ipb){
	int h;
	struct pqt *spqt;
	struct pqt *mpqt;

	mpqt = (struct pqt *)malloc(sizeof(struct pqt));
	mpqt->mac.octet[0]=mac->octet[0];
	mpqt->mac.octet[1]=mac->octet[1];
	mpqt->mac.octet[2]=mac->octet[2];
	mpqt->mac.octet[3]=mac->octet[3];
	mpqt->mac.octet[4]=mac->octet[4];
	mpqt->mac.octet[5]=mac->octet[5];
	mpqt->ip_d=ipb;
	mpqt->next=NULL;

	h = sens_hash(mac, ipb);
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

void sens_reload(void){
	sens_free();
	sens_init();
}

int sens_exist(data_mac *mac, data_ip ipb){
		int h;
		struct pqt *spqt;

		h = sens_hash(mac, ipb);
		spqt = (struct pqt *)pqt_h[h];
		if(spqt==NULL)return(FALSE);
		while(spqt != NULL){
			if(spqt->ip_d.ip==ipb.ip && \
				spqt->mac.octet[0]==mac->octet[0] && \
				spqt->mac.octet[1]==mac->octet[1] && \
				spqt->mac.octet[2]==mac->octet[2] && \
				spqt->mac.octet[3]==mac->octet[3] && \
				spqt->mac.octet[4]==mac->octet[4] && \
				spqt->mac.octet[5]==mac->octet[5] )return(TRUE);
			spqt=spqt->next;
		}
		return(FALSE);
}

/* fait le hachage */
unsigned int sens_hash(data_mac *mac, data_ip ipb){
	unsigned int v;

	v = (mac->octet[4] + mac->octet[5] + ipb.ip) % HASH_SIZE;
	return(v);
}


