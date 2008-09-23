#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "data.h"
#include "log.h"
#include "config.h"
#include "loadconfig.h"

/* Taille de la table de hachage (nombre premier) */
#define HASH_SIZE 1999
#define HASH_B 256

/* conversion bin -> hexa */
const char conv[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

/* conversion hexa -> bin */
const unsigned char vnoc[103] = {
	0,0,0,0,0,0,0,0,0,0,            /*  9 */
	0,0,0,0,0,0,0,0,0,0,            /* 19 */
	0,0,0,0,0,0,0,0,0,0,            /* 29 */
	0,0,0,0,0,0,0,0,0,0,            /* 39 */
	0,0,0,0,0,0,0,0,0,1,            /* 49 */
	2,3,4,5,6,7,8,9,0,0,            /* 59 */
	0,0,0,0,0,10,11,12,13,14,       /* 69 */
	15,0,0,0,0,0,0,0,0,0,           /* 79 */
	0,0,0,0,0,0,0,0,0,0,            /* 89 */
	0,0,0,0,0,0,0,10,11,12,         /* 99 */
	13,14,15                        /* 102 */
};

unsigned int data_size;

unsigned int data_hash(data_mac *mac);
unsigned int data_cmp(data_mac *mac1, data_mac *mac2);

/* unite de la table */
typedef struct __data_element {
	data_pack data;
	struct __data_element *next;
} data_element;

/* pointeur sur unit� */
typedef data_element * p_data_element;

/* Tableau d'adresses mac */
p_data_element *data_tab;

/* initialise la memoire */
void data_init(void){
	p_data_element *init_null;

	/* reserve le tableau de pointeurs de la taille du hash */
	data_tab = (p_data_element *)malloc(HASH_SIZE * sizeof(p_data_element));

	/* met tous ses element a NULL */
	init_null = data_tab;
	while(init_null < data_tab + HASH_SIZE){
		*init_null = NULL;
		init_null++;
	}

	data_size = 0;
}

/* libere la memoire */
void data_reset(void){
	p_data_element *init_null;
	data_element *del, *delnext;
	init_null = data_tab;
	while(init_null < data_tab + HASH_SIZE){
		del = *init_null;
		while(1){
			if(del != NULL){
				delnext = (*del).next;
				free(del);
				del = delnext;
			} else {
				break;
			}
	}
		*init_null = NULL;
		init_null++;
	}
}

/* libere la memoire */
void data_close(void){
	data_reset();
	free(data_tab);
}

/* ajoute une @ mac a la table */
void data_add(data_mac *mac, int status,  int ip){
	p_data_element *add;
	data_element *libre;
	#ifdef DEBUG 
	unsigned char buf[18];
	#endif

	if(data_size >= config[CF_MAXENTRY].valeur.integer){
		logmsg(LOG_ERR, "[%s %i] memory up to %i entries: flushing data", __FILE__, __LINE__, config[CF_MAXENTRY].valeur.integer);
		data_clean(0);
	}
	
	/* possitionement de la nouvelle donn� en memoire */
	add = data_tab;
	add += data_hash(mac);

	/* recherche d'un emplacement libre */
	if(*add != NULL){
		libre = *add;
		while((*libre).next!= NULL){
			libre = (*libre).next;
		}
		add = &((*libre).next);
	}

	/* creation et malloc d'un nouveau data_element (nouvelle mac) dans add */
	libre = (data_element *)malloc(sizeof(data_element));

	if(libre ==NULL){
		logmsg(LOG_ERR, "[%s %i] Memory allocation error", __FILE__, __LINE__);
	} else {
		(*libre).data.mac.octet[0] = (*mac).octet[0];
		(*libre).data.mac.octet[1] = (*mac).octet[1];
		(*libre).data.mac.octet[2] = (*mac).octet[2];
		(*libre).data.mac.octet[3] = (*mac).octet[3];
		(*libre).data.mac.octet[4] = (*mac).octet[4];
		(*libre).data.mac.octet[5] = (*mac).octet[5];
		(*libre).data.flag = status;
		(*libre).data.ip.ip = ip;
		(*libre).data.timestamp = time(NULL);
		(*libre).data.lastalert[0] = 0;
		(*libre).data.lastalert[1] = 0;
		(*libre).data.lastalert[2] = 0;
		(*libre).data.lastalert[3] = 0;
		(*libre).data.lastalert[4] = 0;
		(*libre).data.lastalert[5] = 0;
		(*libre).data.lastalert[6] = 0;
		(*libre).data.request = 0;
		(*libre).next = NULL;
		*add = libre;
		#ifdef DEBUG
			data_tomac(*mac, buf);
			logmsg(LOG_DEBUG, "[%s %i] Address %s add in memory at 0x%x",
				__FILE__, __LINE__, buf, (unsigned int)add);
		#endif
		data_size++;
	}
}

/* dump du hash */
void data_dump(void){
	p_data_element *init_null;
	data_element *del;
	unsigned char s_mac[18];
	FILE *fp;
	char msg[128];
	
	if(config[CF_LEASES].valeur.string[0] != 0){
		fp = fopen(config[CF_LEASES].valeur.string, "w");
		if(fp == NULL){
			logmsg(LOG_ERR, "[%s %i] Can't open file [%s]", __FILE__, __LINE__, 
				config[CF_LEASES].valeur.string);
			exit(1);
		}
	} else {
		return;
	}
	
	init_null = data_tab;
	while(init_null < data_tab + HASH_SIZE){
		del = *init_null;
		while(1){
			if(del != NULL){
				data_tomac((*del).data.mac, s_mac);
				if(
					(
					 	config[CF_DMPBL].valeur.integer == TRUE 
						&& del[0].data.flag == DENY
					) || (
						config[CF_DMPWL].valeur.integer == TRUE 
						&& del[0].data.flag == ALLOW
					) || (
						config[CF_DMPAPP].valeur.integer == TRUE 
						&& del[0].data.flag == APPEND
					)
				){
					if(del[0].data.ip.ip != 0){
						snprintf(msg, 128, "%s %i.%i.%i.%i\n", s_mac, 
							del[0].data.ip.bytes[0], del[0].data.ip.bytes[1], 
							del[0].data.ip.bytes[2], del[0].data.ip.bytes[3]);
						fputs(msg, fp);
					}
				}
				del = (*del).next;
			} else {
				break;
			}
		}
		init_null++;
	}
	fclose(fp);
}

/* netoyage des anciens */
void data_clean(int timeout){
	p_data_element *init_null;
	data_element *actu;
	data_element *last;
	data_element *next;
	
	init_null = data_tab;
	while(init_null < data_tab + HASH_SIZE){
		actu = *init_null;
		last = (data_element *)init_null;
		while(1){
			if(actu != NULL){
				next = (*actu).next;
				if((*actu).data.flag == APPEND && ( time(NULL) - (*actu).data.timestamp ) >= timeout){
					if(last==(data_element *)init_null){
						*init_null = next;
					}else{
						(*last).next = next;
					}
					free(actu);
					data_size--;
					flagdump = TRUE;
				} else {
					last = actu;
				}
				actu = next;
			} else {
				break;
			}
		}
		init_null++;
	}
}


			
/* cherche si @ mac existe */
data_pack *data_exist(data_mac *mac){
	data_element *question;
	p_data_element *emplacement;

	/* va chercher le segement dans la table de hachage */
	emplacement = data_tab;
	emplacement += data_hash(mac);
	question = *emplacement;
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Test address 0x%x -> %x", __FILE__, __LINE__, (unsigned int)emplacement, (unsigned int)question);
	#endif

	if(question == NULL)return(NULL);

	while(data_cmp(&((*question).data.mac), mac) == 1){
		if(question->next != NULL){
			question = (*question).next;
		} else {
			return(NULL);
		}
	}
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Address founded", __FILE__, __LINE__);
	#endif
	return(&(question->data));
}

/* fait le hachage */
unsigned int data_hash(data_mac *mac){
	unsigned int v = 0;
	unsigned int i = 0;

	i = 4;
	while(i<6){
		v = (v * HASH_B + mac[0].octet[i]) % HASH_SIZE;
		i++;
	}
	return(v);
}

unsigned int data_cmp(data_mac *mac1, data_mac *mac2){
	if((*mac1).octet[0] != (*mac2).octet[0]) return(1);
	if((*mac1).octet[1] != (*mac2).octet[1]) return(1);
	if((*mac1).octet[2] != (*mac2).octet[2]) return(1);
	if((*mac1).octet[3] != (*mac2).octet[3]) return(1);
	if((*mac1).octet[4] != (*mac2).octet[4]) return(1);
	if((*mac1).octet[5] != (*mac2).octet[5]) return(1);
	return(0);
}

/* conversion du type mac vers un string lisible */
void data_tomac(data_mac bin, unsigned char *buf){
	buf[0]=conv[bin.octet[0]>>4];
	buf[1]=conv[bin.octet[0]&0x0f];
	buf[2]=':';
	buf[3]=conv[bin.octet[1]>>4];
	buf[4]=conv[bin.octet[1]&0x0f];
	buf[5]=':';
	buf[6]=conv[bin.octet[2]>>4];
	buf[7]=conv[bin.octet[2]&0x0f];
	buf[8]=':';
	buf[9]=conv[bin.octet[3]>>4];
	buf[10]=conv[bin.octet[3]&0x0f];
	buf[11]=':';
	buf[12]=conv[bin.octet[4]>>4];
	buf[13]=conv[bin.octet[4]&0x0f];
	buf[14]=':';
	buf[15]=conv[bin.octet[5]>>4];
	buf[16]=conv[bin.octet[5]&0x0f];
	buf[17]=0;
}

int data_toip(unsigned char *ip){
	int ii;
	int pos, rang;
	data_ip ip_32;

	pos = 0;
	rang=0;
	ip_32.ip= 0;
	for(ii=0; (ii <= 15 && ip[ii] != 0); ii++){
		if(ip[ii]=='.'){
			pos++;
			rang=0;
			continue;
		}
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %i] ip_32.bytes[%i] = (ip_32.bytes[%i](%i) * 10) + ip[%i](%c - %i) - 48 = %i;", __FILE__, __LINE__, pos, pos, ip_32.bytes[pos], ii, ip[ii], ip[ii], (ip_32.bytes[pos]*10)+ip[ii]-48);
		#endif
		ip_32.bytes[pos] = (ip_32.bytes[pos] * 10) + ip[ii] - 48;
		rang++;
	}

	return ip_32.ip;
}

/* conversion d'un string lisible (table arp du noyaux, ...) vers un type mac */
void data_tohex(unsigned char *macaddr, data_mac *voila){
	voila->octet[0] =  vnoc[macaddr[1]];
	voila->octet[0] += vnoc[macaddr[0]] * 16;
	voila->octet[1] =  vnoc[macaddr[4]];
	voila->octet[1] += vnoc[macaddr[3]] * 16;
	voila->octet[2] =  vnoc[macaddr[7]];
	voila->octet[2] += vnoc[macaddr[6]] * 16;
	voila->octet[3] =  vnoc[macaddr[10]];
	voila->octet[3] += vnoc[macaddr[9]] * 16;
	voila->octet[4] =  vnoc[macaddr[13]];
	voila->octet[4] += vnoc[macaddr[12]] * 16;
	voila->octet[5] =  vnoc[macaddr[16]];
	voila->octet[5] += vnoc[macaddr[15]] * 16;
	voila->octet[6] =  vnoc[macaddr[19]];
	voila->octet[6] += vnoc[macaddr[18]] * 16;
}

