#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "data.h"
#include "sens_timeouts.h"
#include "log.h"
#include "config.h"
#include "loadconfig.h"

/* Taille de la table de hachage (nombre premier) */
/* hash table size ; this number must be primary number */
#define HASH_SIZE 1999

// hash function
#define sens_timeout_hash(a, b) ( ( (u_char)(a->octet[4]) + (u_char)(a->octet[5]) + \
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
	struct tmouts *dst_tmout;
	int h;

	// get free timeout node
	if(free_start==NULL){
		logmsg(LOG_WARNING, "[%s %d] No authorized request detection timeout avalaible, "
			"more than %d timeouts currently used",
			__FILE__, __LINE__, MAX_DATA);
		return;
	}
	new_tmout = free_start;
	free_start = new_tmout->next_chain;
	
	new_tmout->mac.octet[0] = mac->octet[0];
	new_tmout->mac.octet[1] = mac->octet[1];
	new_tmout->mac.octet[2] = mac->octet[2];
	new_tmout->mac.octet[3] = mac->octet[3];
	new_tmout->mac.octet[4] = mac->octet[4];
	new_tmout->mac.octet[5] = mac->octet[5];
	new_tmout->ip_d.ip = ipb.ip;
	new_tmout->last = time(NULL);
	new_tmout->prev_hash = NULL;
	new_tmout->next_hash = NULL;
	new_tmout->next_chain = NULL;

	// add entrie in hash
	h = sens_timeout_hash(mac, ipb);
	dst_tmout = tmout_h[h];
	
	// find a free space
	if(dst_tmout == NULL){
		tmout_h[h] = new_tmout;
		new_tmout->prev_hash = (struct tmouts *)&tmout_h[h];
	} else {
		while(dst_tmout->next_hash != NULL){
			dst_tmout=dst_tmout->next_hash;
		}
		dst_tmout->next_hash = new_tmout;
		new_tmout->prev_hash = dst_tmout;
	}

	// add timeout in chain list
	if(used_last == NULL){
		if(used_start != NULL){
			logmsg(LOG_ERR, "[%s %d] Memory error: state not possible",
				__FILE__, __LINE__);
			exit(1);
		}
		used_start = new_tmout;
	} else {
		used_last->next_chain = new_tmout;
	}
	used_last = new_tmout;
}

// if timeout entrie exist: is not expired
int sens_timeout_exist(data_mac *mac, data_ip ipb){
	int h;
	struct tmouts *dst_tmout;

	h = sens_timeout_hash(mac, ipb);
	dst_tmout = tmout_h[h];

	while(dst_tmout != NULL){
		if(dst_tmout->ip_d.ip == ipb.ip &&
		   dst_tmout->mac.octet[0] == mac->octet[0] &&
		   dst_tmout->mac.octet[1] == mac->octet[1] &&
		   dst_tmout->mac.octet[2] == mac->octet[2] &&
		   dst_tmout->mac.octet[3] == mac->octet[3] &&
		   dst_tmout->mac.octet[4] == mac->octet[4] &&
		   dst_tmout->mac.octet[5] == mac->octet[5] ){
			return(TRUE);
		}
		dst_tmout = dst_tmout->next_hash;
	}
	return(FALSE);
}

// delete timeouts expires
void sens_timeout_clean(void) {
	struct tmouts *t_run;
	time_t time_act;

	time_act = time(NULL);
	t_run = used_start;

	while(t_run != NULL && 
	      time_act - t_run->last >= config[CF_ANTIFLOOD_INTER].valeur.integer){
		// if previous data is hash base
		if(t_run->prev_hash >= (struct tmouts *)&tmout_h[0] && 
		   t_run->prev_hash <= (struct tmouts *)&tmout_h[HASH_SIZE - 1] ){
			*(struct tmouts **)t_run->prev_hash = t_run->next_hash;
		} else {
			t_run->prev_hash->next_hash = t_run->next_hash;
		}
		if(t_run->next_hash != NULL){
			t_run->next_hash->prev_hash = t_run->prev_hash;
		}
		used_start = t_run->next_chain;
		if(used_start == NULL) used_last = NULL;
		t_run->next_chain = free_start;
		free_start = t_run;
		t_run = used_start;
	}
}

