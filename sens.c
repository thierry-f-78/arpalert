/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: sens.c 274 2006-10-12 15:31:12Z  $
 *
 */

#include "config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "arpalert.h"
#include "loadconfig.h"
#include "data.h"
#include "sens.h"
#include "log.h"

// hash table size ; this number must be primary number
#define HASH_SIZE 4096

/* debug: */
// #define DEBUG 1

/* HACHAGE */
#define SENS_HASH(x, y, z) ({ \
	u_int32_t a, b, c; \
	a = (*(u_int16_t*)&(x)->ETHER_ADDR_OCTET[0]) ^ (*(u_int16_t*)&(x)->ETHER_ADDR_OCTET[4]); \
	b = a + ( ( (x)->ETHER_ADDR_OCTET[2] ^ (x)->ETHER_ADDR_OCTET[3] ) << 16 ); \
	c = a ^ ( b >> 12 ); \
	a = ((u_int16_t)(y)) ^ ( ((u_int32_t)(y)) >> 20 ) ^ ( ((u_int8_t)(y)) >> 12 ); \
	b = ((u_int16_t)(z)) ^ ( ((u_int32_t)(z)) >> 20 ) ^ ( ((u_int8_t)(z)) >> 12 ); \
	( a ^ b ^ c ) & 0xfff; \
})

#define BUF_SIZE 1024
#define MAC_ADRESS_MAX_LEN 17
#define IP_ADRESS_MAX_LEN 15
#define MASK_MAX_LEN 2

// masks 
#define END_OF_MASKS 0x00000001

// conv binary mask to ip style mask
const u_int32_t dec_to_bin[33] = {
	0x00000000,
	0x00000080,
	0x000000c0,
	0x000000e0,
	0x000000f0,
	0x000000f8,
	0x000000fc,
	0x000000fe,
	0x000000ff,
	0x000080ff,
	0x0000c0ff,
	0x0000e0ff,
	0x0000f0ff,
	0x0000f8ff,
	0x0000fcff,
	0x0000feff,
	0x0000ffff,
	0x0080ffff,
	0x00c0ffff,
	0x00e0ffff,
	0x00f0ffff,
	0x00f8ffff,
	0x00fcffff,
	0x00feffff,
	0x00ffffff,
	0x80ffffff,
	0xc0ffffff,
	0xe0ffffff,
	0xf0ffffff,
	0xf8ffffff,
	0xfcffffff,
	0xfeffffff,
	0xffffffff
};

/* structures */
struct pqt {
	struct ether_addr mac;
	struct in_addr ip_d;
	struct in_addr mask;
	struct pqt *next;
};

/* hash */
struct pqt *pqt_h[HASH_SIZE];

/* mask list */
struct in_addr used_masks[33];

void sens_init(void) {
	int fd;
	char buf[BUF_SIZE];
	int read_size;
	char *parse;
	char *find;
	char current[IP_ADRESS_MAX_LEN + MASK_MAX_LEN + 2];
	int  current_count=0;
	char cur_dec = 0; // current type read: 0: null; 1: ip; 2: mac; 3: comment
	struct ether_addr last_mac;
	struct in_addr ip;
	struct in_addr binmask;
	u_int32_t mask;
	u_int line = 1;
	int i, j;
	int flag_mask = FALSE;
	char sort_tmp;
	char list_mask[33];

	memset(&pqt_h, 0, HASH_SIZE * sizeof(struct pqt *));
	memset(&list_mask, -1, 33);

	if(config[CF_AUTHFILE].valeur.string == NULL) {
		return;
	}

	// open config file
	fd = open(config[CF_AUTHFILE].valeur.string, O_RDONLY);
	if(fd == -1){
		logmsg(LOG_ERR, "[%s %i] didn't find authorization file %s",
		       __FILE__, __LINE__, config[CF_AUTHFILE].valeur.string);
		exit(1);
	}

	// parsing acces file
	current[0] = 0;
	do {
		read_size = read(fd, buf, BUF_SIZE);
		if(read_size < BUF_SIZE){
			buf[read_size] = '\n';
			read_size++;
		}

		parse = buf;
		while(parse < &buf[read_size]){
			if(*parse == '\r'){
				parse++;
				continue;
			}

			if(*parse == ' '  ||
			   *parse == '\t' ||
			   *parse == ']' ||
			   *parse == '\n' ){
				if(cur_dec == 1){
					current[current_count] = 0;
					find = &current[0];
					mask = 32;
					while(*find != 0){
						if(*find=='/'){
							*find = 0;
							find++;
							mask = atoi(find);
							break;
						}
						find++;
					}
					//ip = str_to_ip(current);
					ip.s_addr = inet_addr(current);

					// network address validation
					if( (ip.s_addr & dec_to_bin[mask]) != ip.s_addr){
						logmsg(LOG_ERR, "[%s %i] error in config file \"%s\" "
						       "at line %d: the value %s/%u are incorrect",
						       __FILE__, __LINE__, config[CF_AUTHFILE].valeur.string,
						       line, current, mask);
						exit(1);
					}

					// add this network value in hash
					binmask.s_addr = dec_to_bin[mask];
					sens_add(&last_mac, ip, binmask);
					
					// find next free position in mask_list or mask itself
					i=0;
					while(list_mask[i] != mask && list_mask[i] != -1){
						i++;
					}
					if(list_mask[i] == -1){
						list_mask[i] = mask;
					}
					
					current[0] = 0;
					cur_dec = 0;
				}
				if(cur_dec == 2){
					current[current_count] = 0;
					str_to_mac(current, &last_mac);
					current[0] = 0;
					cur_dec = 0;
				}
				if(cur_dec == 3 && *parse == '\n'){
					cur_dec = 0;
				}
				if(*parse == '\n'){
					line++;
				}
				current_count = 0;
				parse++;
				continue;
			}
			
			if(*parse == '#'){
				cur_dec = 3;
				parse++;
				continue;
			}
			
			if(*parse == '[' && cur_dec != 3){
				cur_dec = 2;
				parse++;
				continue;
			}

			if(cur_dec != 2 && cur_dec != 3) cur_dec = 1;
			
			if(cur_dec == 1){
				if(current_count == IP_ADRESS_MAX_LEN &&
				   flag_mask == FALSE && *parse != '/'){
					// syntax error
					logmsg(LOG_ERR, "[%s %d] syntax error decoding IP at line %d",
					       __FILE__, __LINE__, line);
					exit(1);
				}
				if(current_count == IP_ADRESS_MAX_LEN + MASK_MAX_LEN + 1 &&
				   flag_mask == TRUE){
					logmsg(LOG_ERR, "[%s %d] syntax error decoding IP at line %d",
					       __FILE__, __LINE__, line);
					exit(1);
				}
				current[current_count] = *parse;
				if(*parse == '/'){
					flag_mask = TRUE;
				}
				current_count ++;
				parse ++;
				continue;
			}
			
			if(cur_dec == 2){
				if(current_count == MAC_ADRESS_MAX_LEN){
					//syntax error
					logmsg(LOG_ERR, "[%s %d] syntax error decoding IP at line %d",
					       __FILE__, __LINE__, line);
					exit(1);
				}
				current[current_count] = *parse;
				current_count ++;
				parse++;
				continue;
			}
			
			parse++;
		}
	} while(read_size == BUF_SIZE);

	close(fd);
	
	// sort list_mask
	for(i=0; i<32; i++){
		for(j=32; j>i; j--){
			if(list_mask[j] > list_mask[j-1]){
				sort_tmp = list_mask[j-1];
				list_mask[j-1] = list_mask[j];
				list_mask[j] = sort_tmp;
			}
		}
		// convert decimal mask to binary mask
		if(list_mask[i] != -1){
			used_masks[i].s_addr = dec_to_bin[(u_char)list_mask[i]];
		} else {
			used_masks[i].s_addr = END_OF_MASKS;
		}
	}
}

// add data to hash
void sens_add(struct ether_addr *mac, struct in_addr ipb, struct in_addr mask){
	u_int h;
	struct pqt *mpqt;

	mpqt = (struct pqt *)malloc(sizeof(struct pqt));
	if(mpqt == NULL){
		logmsg(LOG_ERR, "[%s %d] allocation memory error",
		       __FILE__, __LINE__);
		exit(1);
	}
	DATA_CPY(&mpqt->mac, mac);
	mpqt->ip_d = ipb;
	mpqt->mask = mask;

	// calculate hash
	h = SENS_HASH(mac, ipb.s_addr, mask.s_addr);
	// find a free space
	mpqt->next = pqt_h[h];
	pqt_h[h] = mpqt;
}

void sens_free(void){
	int i;
	struct pqt *free_pqt;
	struct pqt *current_pqt;

	for(i=0; i<HASH_SIZE; i++){
		current_pqt = pqt_h[i];
		while(current_pqt != NULL){
			free_pqt = current_pqt;
			current_pqt = current_pqt->next;
			free(free_pqt);
		}
		pqt_h[i] = NULL;
	}
}

void sens_reload(void){
	sens_free();
	sens_init();
}

int sens_exist(struct ether_addr *mac, struct in_addr ipb){
	u_int h;
	struct pqt *spqt;
	struct in_addr *masks = &used_masks[0];
	struct in_addr ip;

	// test all masks
	while((*masks).s_addr != END_OF_MASKS){
		
		// apply mask
		ip.s_addr = ipb.s_addr & (*masks).s_addr;

		// get data in hash
		h = SENS_HASH(mac, ip.s_addr, (*masks).s_addr);
		spqt = pqt_h[h];

		// find data
		while(spqt != NULL){
			if(spqt->ip_d.s_addr == ip.s_addr &&
			   spqt->mask.s_addr == (*masks).s_addr &&
			   DATA_CMP(&spqt->mac, mac) == 0 ){
				return(TRUE);
			}
			spqt = spqt->next;
		}
		masks++;
	}
	return(FALSE);
}

