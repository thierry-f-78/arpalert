/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: sens_timeouts.c 87 2006-05-09 07:58:27Z thierry $
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arpalert.h"
#include "data.h"
#include "sens_timeouts.h"
#include "log.h"
#include "loadconfig.h"

/* Taille de la table de hachage (nombre premier) */
/* hash table size ; this number must be primary number */
#define HASH_SIZE 1999

// hash function
#define SENS_TIMEOUT_HASH(a, b) ( ( (u_char)(a->octet[4]) + (u_char)(a->octet[5]) + \
                                (u_int32_t)(b.ip) ) % HASH_SIZE )

// structurs
struct tmouts {
	data_mac mac;
	data_ip ip_d;
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
void sens_timeout_add(data_mac *mac, data_ip ipb){
	struct tmouts *new_tmout;
	int hash;

	// get free timeout node
	if(free_start == NULL){
		logmsg(LOG_WARNING, "[%s %d] No authorized request detection timeout avalaible, "
			"more than %d timeouts currently used",
			__FILE__, __LINE__, MAX_DATA);
		return;
	}
	new_tmout = free_start;
	free_start = new_tmout->next_chain;
	data_cpy(&new_tmout->mac, mac);
	new_tmout->ip_d.ip = ipb.ip;
	new_tmout->last = current_time;
	new_tmout->next_hash = NULL;
	new_tmout->next_chain = NULL;

	// add entrie in hash
	hash = SENS_TIMEOUT_HASH(mac, ipb);
	// find a free space
	new_tmout->next_hash = tmout_h[hash];
	new_tmout->prev_hash = (struct tmouts *)&tmout_h[hash];
	tmout_h[hash] = new_tmout;

	// add timeout in chain list
	if(used_last == NULL){
		used_start = new_tmout;
	} else {
		used_last->next_chain = new_tmout;
	}
	used_last = new_tmout;
}

// check if entrie are in timeout
int sens_timeout_exist(data_mac *mac, data_ip ipb){
	int h;
	struct tmouts *dst_tmout;

	// if timeout entrie exist: is not expired
	h = SENS_TIMEOUT_HASH(mac, ipb);
	dst_tmout = tmout_h[h];

	while(dst_tmout != NULL){
		if(dst_tmout->ip_d.ip == ipb.ip &&
		   data_cmp(&dst_tmout->mac, mac)){
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
			t_run->prev_hash = t_run->next_hash;
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

