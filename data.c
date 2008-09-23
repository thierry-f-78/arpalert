/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: data.c 275 2006-10-12 15:39:24Z  $
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "arpalert.h"
#include "data.h"
#include "log.h"
#include "loadconfig.h"

// hash table size (must be a primary number)
//#define HASH_SIZE 1999
#define HASH_SIZE 4096

// conversion hexa -> bin
const u_char hex_conv[103] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /*  9 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* 19 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* 29 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* 39 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 1,    /* 49 */
	2, 3, 4, 5, 6, 7, 8, 9, 0, 0,    /* 59 */
	0, 0, 0, 0, 0, 10,11,12,13,14,   /* 69 */
	15,0, 0, 0, 0, 0, 0, 0, 0, 0,    /* 79 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* 89 */
	0, 0, 0, 0, 0, 0, 0, 10,11,12,   /* 99 */
	13,14,15                         /* 102 */
};

// actual number of datas
unsigned int data_size;

//unsigned int data_mac_hash(data_mac *mac);
// retourn un resultat sur 12 bits
#define DATA_MAC_HASH(x) ({ \
   u_int32_t a, b; \
	a = (*(u_int16_t*)&(x)->ETHER_ADDR_OCTET[0]) ^ (*(u_int16_t*)&(x)->ETHER_ADDR_OCTET[4]); \
	b = a + ( ( (x)->ETHER_ADDR_OCTET[2] ^ (x)->ETHER_ADDR_OCTET[3] ) << 16 ); \
	( a ^ ( b >> 12 ) ) & 0xfff; \
})

//unsigned int data_ip_hash(data_mac *mac);
// retourn un resultat sur 12 bits
#define DATA_IP_HASH(x) ({ \
	u_int32_t a, b, c; \
	a = (u_int16_t)(x) & 0xfff; \
	b = (u_int32_t)(x) >> 20; \
	c = (u_int8_t)(x) >> 12; \
	a ^ b ^ c; \
})

// hash table cell
struct data_element {
	data_pack data;
	struct data_element *next_mac;
	struct data_element *next_ip;
};

// hash mac table base
struct data_element *data_mac_tab[HASH_SIZE];

// hash ip table base
struct data_element *data_ip_tab[HASH_SIZE];

// dump mask
int dump_mask;

// init memory
void data_init(void){

	memset(data_mac_tab, 0, HASH_SIZE * sizeof(struct data_element *));
	memset(data_ip_tab, 0, HASH_SIZE * sizeof(struct data_element *));
	data_size = 0;

	// compute mask of allowed data dump
	dump_mask =	config[CF_DMPBL].valeur.integer * DENY +
	            config[CF_DMPWL].valeur.integer * ALLOW +
	            config[CF_DMPAPP].valeur.integer * APPEND;
}

// free memory
void data_reset(void){
	struct data_element *del;
	struct data_element *delnext;
	int step;

	for(step=0; step<HASH_SIZE; step++){
		delnext = data_mac_tab[step];
		while(delnext != NULL){
			del = delnext;
			delnext = delnext->next_mac;
			free(del);
		}
		data_mac_tab[step] = NULL;
		data_ip_tab[step] = NULL;
	}
}

// add mac address in hash
void data_add_field(struct ether_addr *mac, int status, struct in_addr ip, u_int32_t field){
	data_pack *datap;
	
	datap = data_add(mac, status, ip);
	datap->alerts = field;
}

// add mac address in hash
data_pack *data_add(struct ether_addr *mac, int status, struct in_addr ip){
	struct data_element *add;
	struct data_element *libre;
	int mac_hash;
	int ip_hash;
	#ifdef DEBUG 
	char buf[18];
	#endif

	if(data_size >= config[CF_MAXENTRY].valeur.integer){
		logmsg(LOG_ERR, "[%s %i] memory up to %i entries: flushing data",
		       __FILE__, __LINE__, config[CF_MAXENTRY].valeur.integer);
		data_clean(0);
	}
	
	// allocate memory for new data
	libre = (struct data_element *)malloc(sizeof(struct data_element));

	if(libre == NULL){
		logmsg(LOG_ERR, "[%s %i] Memory allocation error", __FILE__, __LINE__);
		exit(1);
	}

	// make data structur
	DATA_CPY(&libre->data.mac, mac);
	libre->data.flag = status;
	libre->data.ip.s_addr = ip.s_addr;
	libre->data.timestamp = current_time;
	libre->data.lastalert[0] = 0;
	libre->data.lastalert[1] = 0;
	libre->data.lastalert[2] = 0;
	libre->data.lastalert[3] = 0;
	libre->data.lastalert[4] = 0;
	libre->data.lastalert[5] = 0;
	libre->data.lastalert[6] = 0;
	libre->data.request = 0;
	libre->data.alerts = 0;
	data_size++;

	// calculate mac hash
	mac_hash = DATA_MAC_HASH(mac);
	add = data_mac_tab[mac_hash];

	// find free space
	libre->next_mac = data_mac_tab[mac_hash];
	data_mac_tab[mac_hash] = libre;
	
	// index ip
	if(ip.s_addr != 0 && data_ip_exist(ip) == NULL ){
			
		// calculate ip hash
		ip_hash = DATA_IP_HASH(ip.s_addr);
		// find free space in ip hash
		libre->next_ip = data_ip_tab[ip_hash];
		data_ip_tab[ip_hash] = libre;

	} else {
		libre->next_ip = NULL;
	}
	
	#ifdef DEBUG
	MAC_TO_STR(mac[0], buf);
	logmsg(LOG_DEBUG, "[%s %i] Address %s add in hash",
	       __FILE__, __LINE__, buf);
	#endif

	return(&libre->data);
}

// add ip in index
void index_ip(data_pack *to_index){
	struct ether_addr *mac;
	struct data_element *find;
	int hash;

	mac = &to_index->mac;
	hash = DATA_MAC_HASH(mac);
	find = data_mac_tab[hash];

	while(&find->data != to_index){
		find = find->next_mac;
	}

	// calculate ip hash
	hash = DATA_IP_HASH(to_index->ip.s_addr);
	// add data
	find->next_ip = data_ip_tab[hash];
	data_ip_tab[hash] = find;
}

// delete indexed ip
void unindex_ip(u_int32_t ip){
	struct data_element *previous;
	struct data_element *find;
	int hash;
		  
	// calculate ip hash
	hash = DATA_IP_HASH(ip);
	find = data_ip_tab[hash];

	// find entry
	previous = (struct data_element *)&data_ip_tab[hash];
	while(find != NULL && find->data.ip.s_addr != ip) {
		previous = (struct data_element *)&find->next_ip;
		find = find->next_ip;
	}

	// delete hash entry
	if(find != NULL){
		previous = find->next_ip;
		find->next_ip = NULL;
	}
}

// dump hash data
void data_dump(void){
	struct data_element *dump;
	int step;
	int fp;
	int len;
	char msg[35]; //mac(17) + ip(15) + spc + \n + \0

	// if no data dump file
	if(config[CF_LEASES].valeur.string == NULL ||
	   config[CF_LEASES].valeur.string[0] == 0) {
		return;
	}
	
	// open file
	fp = open(config[CF_LEASES].valeur.string, O_WRONLY | O_CREAT | O_TRUNC, 
	          S_IRWXO | S_IRWXG | S_IRWXU);

	// error check
	if(fp == -1){
		logmsg(LOG_ERR, "[%s %i] Can't open file [%s]", __FILE__, __LINE__, 
		       config[CF_LEASES].valeur.string);
		exit(1);
	}

	// parse hash table
	for(step=0; step<HASH_SIZE; step++){
		dump = data_mac_tab[step];
		while(dump != NULL){
			// dump
			if( ( dump_mask & dump->data.flag) != 0 ){
				if(dump->data.ip.s_addr != 0){
					len = snprintf(msg, 35, "%02x:%02x:%02x:%02x:%02x:%02x %s\n",
					              dump->data.mac.ETHER_ADDR_OCTET[0], dump->data.mac.ETHER_ADDR_OCTET[1],
					              dump->data.mac.ETHER_ADDR_OCTET[2], dump->data.mac.ETHER_ADDR_OCTET[3],
					              dump->data.mac.ETHER_ADDR_OCTET[4], dump->data.mac.ETHER_ADDR_OCTET[5], 
					              inet_ntoa(dump->data.ip));
					write(fp, msg, len);
				}
			}

			// get next data
			dump = dump->next_mac;
		}
	}

	// close file
	if(close(fp) == -1){
		logmsg(LOG_ERR, "[%s %i] Can't close file [%s]", __FILE__, __LINE__, 
		       config[CF_LEASES].valeur.string);
		exit(1);
	}
}

// clean old detected mac adresses
void data_clean(int timeout){
	struct data_element *clean;
	struct data_element *next;
	int step;
	
	// parse hash table
	for(step=0; step<HASH_SIZE; step++){
		clean = data_mac_tab[step];
		while(clean != NULL){
				
			if(
			   clean->data.flag == APPEND &&
			   ( current_time - clean->data.timestamp ) >= timeout
			){
				next = clean->next_mac;
				free(clean);
				clean = next;
				data_size--;
				flagdump = TRUE;
			} else {
				// get next data
				clean = clean->next_mac;
			}
		}
	}
}

// get ip in ip hash
data_pack *data_ip_exist(struct in_addr ip){
	struct data_element *find;
	int hash;

	// calculate hash
	hash = DATA_IP_HASH(ip.s_addr);
	find = data_ip_tab[hash];

	while(find != NULL){
		if(find->data.ip.s_addr == ip.s_addr){
			return( &find->data );
		}
		find = find->next_ip;
	}
	return(NULL);
}

// get mac in hash
data_pack *data_exist(struct ether_addr *mac){
	struct data_element *find;
	int hash;

	// calculate hash
	hash = DATA_MAC_HASH(mac);
	find = data_mac_tab[hash];

	while(find != NULL){
		if(DATA_CMP(&find->data.mac, mac) == 0){
			return( &find->data );
		}
		find = find->next_mac;
	}
	return(NULL);
}

// translate string ip to u_int32_t
/*
u_int32_t str_to_ip(char *ip){
	char *parse;
	char *begin;
	u_int conv;
	int count = 3;
	struct in_addr ip_32;
	char end_char;

	begin = ip;
	parse = ip;
	while(TRUE){
		if(*parse == '.' || parse - ip == 15 || *parse == 0){
			end_char = *parse;
			*parse = 0;
			conv = atoi(begin);
			if(conv > 0xff){
				logmsg(LOG_ERR, "[%s %d] IP Error: octet %s incorrect",
				       __FILE__, __LINE__, begin);
			}
			if(count < 0){
				logmsg(LOG_ERR, "[%s %d] IP Error: error in format",
				       __FILE__, __LINE__);
			}
			ip_32.bytes[count] = (u_char)conv;
			*parse = end_char;
			if(parse - ip == 15 || *parse == 0){
				break;
			}
			count--;
			parse++;
			begin = parse;
			continue;
		}		
		else if(*parse >= '0' && *parse <= '9'){
			parse++;
			continue;
		}
		else {
			logmsg(LOG_ERR, "[%s %d] IP Error: unexpected value: %c",
			       __FILE__, __LINE__, *parse);
			parse++;
		}
	}

	if(count != 0){
		logmsg(LOG_ERR, "[%s %d] IP Error: error in format",
		       __FILE__, __LINE__);
	}
	
	return ip_32.ip;
}
*/

// translate string mac to binary mac
void str_to_mac(char *macaddr, struct ether_addr *to_mac){
	int i;
	
	// format verification
	for(i=0; i<=19; i++) {
		switch(i){
			case 0: case 1: case 3: case 4: case 6:
			case 7: case 9: case 10: case 12: case 13:
			case 15: case 16:
				if(macaddr[i] < 'a' && macaddr[i] > 'f' &&
				   macaddr[i] < 'A' && macaddr[i] > 'F' &&
				   macaddr[i] < '0' && macaddr[i] > '9'){
					logmsg(LOG_ERR, "[%s %d] Litteral MAC conversion error: "
					       "error in format of \"%s\": "
					       "character %d: [a-fA-F0-9] expected",
					       __FILE__, __LINE__, macaddr, i);
					exit(1);
				}
				break;
			case 2: case 5: case 8:
			case 11: case 14:
				if(macaddr[i] != ':'){
					logmsg(LOG_ERR, "[%s %d] Litteral MAC conversion error: "
					       "error in format of \"%s\": "
					       "character %d: ':' expected",
					       __FILE__, __LINE__, macaddr, i);
					exit(1);
				}
				break;
		}
	}

	to_mac->ETHER_ADDR_OCTET[0] =  hex_conv[(u_char)macaddr[1]];
	to_mac->ETHER_ADDR_OCTET[0] += hex_conv[(u_char)macaddr[0]] * 16;
	to_mac->ETHER_ADDR_OCTET[1] =  hex_conv[(u_char)macaddr[4]];
	to_mac->ETHER_ADDR_OCTET[1] += hex_conv[(u_char)macaddr[3]] * 16;
	to_mac->ETHER_ADDR_OCTET[2] =  hex_conv[(u_char)macaddr[7]];
	to_mac->ETHER_ADDR_OCTET[2] += hex_conv[(u_char)macaddr[6]] * 16;
	to_mac->ETHER_ADDR_OCTET[3] =  hex_conv[(u_char)macaddr[10]];
	to_mac->ETHER_ADDR_OCTET[3] += hex_conv[(u_char)macaddr[9]] * 16;
	to_mac->ETHER_ADDR_OCTET[4] =  hex_conv[(u_char)macaddr[13]];
	to_mac->ETHER_ADDR_OCTET[4] += hex_conv[(u_char)macaddr[12]] * 16;
	to_mac->ETHER_ADDR_OCTET[5] =  hex_conv[(u_char)macaddr[16]];
	to_mac->ETHER_ADDR_OCTET[5] += hex_conv[(u_char)macaddr[15]] * 16;
}

