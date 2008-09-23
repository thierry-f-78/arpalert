/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: sens_timeouts.c 223 2006-10-05 19:44:46Z thierry $
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

#include "arpalert.h"
#include "data.h"
#include "sens_timeouts.h"
#include "log.h"
#include "loadconfig.h"

/* hash table size ; this number must be primary number */
#define HASH_SIZE 4096

// hash function
#define SENS_TIMEOUT_HASH(x, y) ({ \
   u_int32_t a, b, c; \
   a = (*(u_int16_t*)&(x)->ETHER_ADDR_OCTET[0]) ^ (*(u_int16_t*)&(x)->ETHER_ADDR_OCTET[4]); \
   b = a + ( ( (x)->ETHER_ADDR_OCTET[2] ^ (x)->ETHER_ADDR_OCTET[3] ) << 16 ); \
   c = a ^ ( b >> 12 ); \
   a = ((u_int16_t)(y)) ^ ( ((u_int32_t)(y)) >> 20 ) ^ ( ((u_int8_t)(y)) >> 12 ); \
   ( a ^ c ) & 0xfff; \
})

// structurs
struct tmouts {
	struct ether_addr mac;
	struct in_addr ip_d;
	time_t last;
	struct tmouts *prev_hash;
	struct tmouts *next_hash;
	struct tmouts *next_chain;
};

// data allocation
#define MAX_DATA 2000
struct tmouts tmouts_table[MAX_DATA];

// hash
struct tmouts *tmout_h[HASH_SIZE];

// free table root
struct tmouts *free_start;

// used table root
// first node used
struct tmouts *used_start;
// last node used
struct tmouts *used_last;

// data_init
void sens_timeout_init(void) {
	int i;
	struct tmouts *gen;

	// set NULL pointers in tmout_h table
	memset(&tmout_h, 0, HASH_SIZE * sizeof(struct tmouts *));
	
	free_start = &tmouts_table[0];
	gen = free_start;
	
	// generate free nodes list
	for(i=1; i<MAX_DATA; i++){
		gen->next_chain = &tmouts_table[i];
		gen = gen->next_chain;
	}
	gen->next_chain = NULL;
	used_start = NULL;
	used_last = NULL;
}

// add new timeout
void sens_timeout_add(struct ether_addr *mac, struct in_addr ipb){
	struct tmouts *new_tmout;
	int hash;

	// get free timeout node
	if(free_start == NULL){
		logmsg(LOG_WARNING,
		       "[%s %d] No authorized request detection timeout avalaible, "
		       "more than %d timeouts currently used",
		       __FILE__, __LINE__, MAX_DATA);
		return;
	}

	new_tmout = free_start;
	free_start = new_tmout->next_chain;
	DATA_CPY(&new_tmout->mac, mac);
	new_tmout->ip_d.s_addr = ipb.s_addr;
	new_tmout->last = current_time;

	// add entrie in hash
	hash = SENS_TIMEOUT_HASH(mac, ipb.s_addr);
	new_tmout->next_hash = tmout_h[hash];
	new_tmout->prev_hash = (struct tmouts *)&tmout_h[hash];
	if(new_tmout->next_hash != NULL){
		new_tmout->next_hash->prev_hash = new_tmout;
	}
	tmout_h[hash] = new_tmout;

	// add timeout in chain list
	new_tmout->next_chain = NULL;
	if(used_last == NULL){
		used_start = new_tmout;
	} else {
		used_last->next_chain = new_tmout;
	}
	used_last = new_tmout;
}

// check if entrie are in timeout
int sens_timeout_exist(struct ether_addr *mac, struct in_addr ipb){
	int h;
	struct tmouts *dst_tmout;

	// if timeout entrie exist: is not expired
	h = SENS_TIMEOUT_HASH(mac, ipb.s_addr);
	dst_tmout = tmout_h[h];

	while(dst_tmout != NULL){
		if(dst_tmout->ip_d.s_addr == ipb.s_addr &&
		   DATA_CMP(&dst_tmout->mac, mac) == 0){
			return(TRUE);
		}
		dst_tmout = dst_tmout->next_hash;
	}
	return(FALSE);
}

// delete timeouts expires
void sens_timeout_clean(void) {
	struct tmouts *t_run;

	t_run = used_start;

	while(t_run != NULL && 
	      current_time - t_run->last >= config[CF_ANTIFLOOD_INTER].valeur.integer){

		// if previous data is hash base
		if(t_run->prev_hash >= (struct tmouts *)&tmout_h[0] && 
		   t_run->prev_hash <= (struct tmouts *)&tmout_h[HASH_SIZE - 1] ){
			// update previous data
			*(struct tmouts **)(t_run->prev_hash) = t_run->next_hash;
		} else {
			// update next data
			t_run->prev_hash->next_hash = t_run->next_hash;
		}

		// update next data
		if(t_run->next_hash != NULL){
			t_run->next_hash->prev_hash = t_run->prev_hash;
		}

		// update used_start chain
		used_start = t_run->next_chain;

		// if used_start is empty, set used_last NULL 
		if(used_start == NULL) {
			used_last = NULL;
		}

		// insert last used at the beginig
		// of the unused chain
		t_run->next_chain = free_start;
		free_start = t_run;

		// get next
		t_run = used_start;
		
	}
}

