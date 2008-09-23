/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: maclist.c 313 2006-10-16 12:54:40Z thierry $
 *
 */

#include "config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "capture.h"
#include "arpalert.h"
#include "maclist.h"
#include "data.h"
#include "loadconfig.h"
#include "log.h"
#include "func_str.h"

#define BUFFER_SIZE 1024
#define MAX_ARGS 20

extern int errno;

void maclist_file(char *file_name, int level){
	char buf[BUFFER_SIZE];
	FILE *file;
	char *args[MAX_ARGS];
	int ligne = 0;
	int arg, blank, i;
	char *parse;
	struct ether_addr mac;
	struct in_addr ip;
	U_INT32_T bitfield;
	struct capt *dev;

	// open file
	file = fopen(file_name, "r");
	if(file == NULL){
		logmsg(LOG_ERR, "[%s %d] fopen: %s\n",
		       __FILE__, __LINE__, strerror(errno));
	}
	
	buf[0] = 0;

	// for each line ..
	while(!feof(file)){
		fgets(buf, BUFFER_SIZE, file);
		ligne ++;

		// parse and return arguments list
		arg = 0;
		bzero(args, sizeof(char *) * MAX_ARGS);
		blank = 1;
		parse = buf;
		while(*parse != 0){
			// caractere nul:
			if(*parse == ' ' || *parse == '\t'){
				*parse = 0;
				blank = 1;
				parse ++;
			}

			// last caracter => quit
			else if( *parse == '#' || *parse == '\n' || *parse == '\r'){
				*parse = 0;
				break;
			}

			// other caracters
			else {
				if(blank == 1){
					args[arg] = parse;
					arg ++;
					// exceed args hard limit
					if(arg == MAX_ARGS) {
						logmsg(LOG_ERR,
						       "file: \"%s\", line %d: exceed args hard limit (%d)",
						       file_name, ligne, MAX_ARGS);
					}
					blank = 0;
				}

				parse ++;
			}
		}

		// proceed args
		if(arg == 0) continue;
	
		// sanity check
		if(arg < 3){
			logmsg(LOG_ERR,
			       "file: \"%s\", line %d: insufficient arguments",
			       file_name, ligne);
			continue;
		}

		// first arg: mac addr
		if(str_to_mac(args[0], &mac) == -1){
			logmsg(LOG_ERR,
			       "file: \"%s\", line %d: mac adress error",
			       file_name, ligne);
			exit(1);
		}

		// convert string ip to numeric IP
		ip.s_addr = inet_addr(args[1]);

		// pointer to interface
		dev = cap_get_interface(args[2]);
		if(dev == NULL){
			logmsg(LOG_ERR,
			       "file: \"%s\", line %d: device \"%s\" not found/used",
			       file_name, ligne, args[2]);
			exit(1);
		}

		// check flags
		bitfield = 0;
		i = 3;
		while(i < arg){
			/**/ if(strcmp(args[i], "ip_change") == 0){
				SET_IP_CHANGE(bitfield);
			}
			else if(strcmp(args[i], "black_listed") == 0){
				SET_BLACK_LISTED(bitfield);
			}
			else if(strcmp(args[i], "unauth_rq") == 0){
				SET_UNAUTH_RQ(bitfield);
			}
			else if(strcmp(args[i], "rq_abus") == 0){
				SET_RQ_ABUS(bitfield);
			}
			else if(strcmp(args[i], "mac_error") == 0){
				SET_MAC_ERROR(bitfield);
			}
			else if(strcmp(args[i], "mac_change") == 0){
				SET_MAC_CHANGE(bitfield);
			}
			else {
				logmsg(LOG_ERR,
				       "file: \"%s\", line %d: flag \"%s\" not availaible",
				       file_name, ligne, args[i]);
			}
			i++;
		}

		// add data
		data_add_field(&mac, level, ip, bitfield, dev);
	}
}

void maclist_load(void){
	if(config[CF_MACLIST].valeur.string != NULL){
		maclist_file(config[CF_MACLIST].valeur.string, ALLOW);
	}

	if(config[CF_BLACKLST].valeur.string != NULL){
		maclist_file(config[CF_BLACKLST].valeur.string, DENY);
	}
}

void maclist_reload(void){
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Reload maclist", __FILE__, __LINE__);
	#endif
	data_reset();
	maclist_load();
}
