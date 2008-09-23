/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: maclist.c 275 2006-10-12 15:39:24Z  $
 *
 */

#include "config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "arpalert.h"
#include "maclist.h"
#include "data.h"
#include "loadconfig.h"
#include "log.h"

#define BUFFER_SIZE 1024

void maclist_file(char *, int);

void maclist_load(void){
	if(config[CF_MACLIST].valeur.string != NULL &&
	   config[CF_MACLIST].valeur.string[0] != 0){
		maclist_file(config[CF_MACLIST].valeur.string, ALLOW);
	}

	if(config[CF_BLACKLST].valeur.string != NULL &&
	   config[CF_BLACKLST].valeur.string[0] != 0){
		maclist_file(config[CF_BLACKLST].valeur.string, DENY);
	}
}

int check_flag(char *flag, u_int32_t *bitfield){
	/**/ if(strcmp(flag, "ip_change") == 0){
		SET_IP_CHANGE(*bitfield);
		return 0;
	}
	else if(strcmp(flag, "black_listed") == 0){
		SET_BLACK_LISTED(*bitfield);
		return 0;
	}
	else if(strcmp(flag, "unauth_rq") == 0){
		SET_UNAUTH_RQ(*bitfield);
		return 0;
	}
	else if(strcmp(flag, "rq_abus") == 0){
		SET_RQ_ABUS(*bitfield);
		return 0;
	}
	else if(strcmp(flag, "mac_error") == 0){
		SET_MAC_ERROR(*bitfield);
		return 0;
	}
	else if(strcmp(flag, "mac_change") == 0){
		SET_MAC_CHANGE(*bitfield);
		return 0;
	}
	else {
		return -1;
	}
}

void maclist_file(char *file, int level){
	// file descriptor
	int fp;

	// read buffer
	char a_buf[BUFFER_SIZE];
	char *buf = a_buf;
	
	// number of data read
	int data_read;
	
	// current data reading 0: mac, 1:ip
	int current_data = 0;

	// indicate analysing comment
	int flag_comment = FALSE;

	// read of mac are begining
	int flag_begin_mac = FALSE;
	
	// read of ip are begining
	int flag_begin_ip = FALSE;
	
	// count mac and ip buffer occupation
	int count = 0;
	
	// line count
	int line = 1;

	// mac and ip) buffers
	char a_str_mac[17];
	char a_str_ip[16];
	char a_str_flag[20];
	char *str_mac = a_str_mac;
	char *str_ip = a_str_ip;
	char *str_flag = a_str_flag;
	u_int32_t alerts = 0;

	// numeric mac
	struct ether_addr mac;

	// numeric ip
	struct in_addr ip;

	// init mac and ip buffers
	memset(str_mac, 0, 17);
	memset(str_ip, 0, 16);

	fp = open(file, O_RDONLY);
	if(fp == -1){
		logmsg(LOG_ERR, "[%s %i] Didn't find file [%s]", __FILE__, __LINE__, file);
		exit(1);
	}

	while((data_read = read(fp, buf, BUFFER_SIZE)) > 0){
		while(data_read > 0){

			data_read--;

			// comments
			if(flag_comment == TRUE){
				if(*buf == '\n'){
					flag_comment = FALSE;
				} else {
					buf++;
					continue;
				}
			}
			if(*buf == '#'){
				flag_comment = TRUE;
				buf++;
				continue;
			}
			
			// ignore blank character
			if(*buf == ' ' || *buf == '\t'){
				if(flag_begin_mac == TRUE){
					flag_begin_mac = FALSE;
					current_data = 1;
					count = 0;
				}
				if(flag_begin_ip == TRUE){
					flag_begin_ip = FALSE;
					current_data = 2;
					count = 0;
				}
				buf++;
				continue;
			}

			// end of line
			if(*buf == '\n'){
				// check last flag
				*str_flag = 0;
				if(str_flag != a_str_flag && check_flag(a_str_flag, &alerts) == -1){
					logmsg(LOG_ERR, "[%s %i] Keywords error at word \"%s\" line %i file %s",
				   	    __FILE__, __LINE__, a_str_flag, line, file);
					exit(1);
				}

				// reset datas and flags
				flag_begin_mac = FALSE;
				flag_begin_ip = FALSE;
				current_data = 0;
				*str_ip = 0;
				str_mac = a_str_mac;
				str_ip = a_str_ip;
				str_flag = a_str_flag;
				count = 0;

				// increment line
				line++;

				// test if mac or ip is virgin
				if(*str_ip == 0 && *str_mac == 0) {
					buf++;
					continue;
				}
			
				// convert string mac to numeric mac
				str_to_mac(str_mac, &mac);

				// convert string ip to numeric IP
				ip.s_addr = inet_addr(str_ip);

				// adding data to the hash table
				// data_add(&mac, level, ip);
				data_add_field(&mac, level, ip, alerts);
			
				// init mac ans ip buffers
				memset(str_mac, 0, 17);
				memset(str_ip, 0, 16);
				alerts = 0;

				buf++;
				continue;
			}

			// copy mac data
			if(current_data == 0){
				if(
					( *buf >= '0' && *buf <= '9' ) ||
					( *buf >= 'a' && *buf <= 'f' ) ||
					( *buf >= 'A' && *buf <= 'F' ) ||
					*buf == ':'
				){
					if(count >= 17){
						logmsg(LOG_ERR, "[%s %i] Mac address format error at line "
						       "%i file %s",
						       __FILE__, __LINE__, line, file);
						exit(1);
					}
					flag_begin_mac = TRUE;
					*str_mac = *buf;
					str_mac++;
					count++;
					buf++;
					continue;
				} else {
					logmsg(LOG_ERR, "[%s %i] Mac address format error at line "
					       "%i file %s: character unexpected",
					       __FILE__, __LINE__, line, file);
					exit(1);
				}
			}
		
			// copy IP data
			if(current_data == 1){
				if(
					( *buf >= '0' && *buf <= '9' ) ||
					*buf == '.'
				){
					if(count >= 15){
						logmsg(LOG_ERR, "[%s %i] IP address error at "
						       "line %i file %s",
						       __FILE__, __LINE__, line);
						exit(1);
					}
					flag_begin_ip = TRUE;
					*str_ip = *buf;
					str_ip++;
					count++;
					buf++;
					continue;
				} else {
					logmsg(LOG_ERR, "[%s %i] IP Address format error at line %i "
					       "file %s: unexpected character",
					       __FILE__, __LINE__, line, file);
					exit(1);
				}
			}
	
			if(current_data == 2){
			   if(*buf == ','){
					*str_flag = 0;
					if(check_flag(a_str_flag, &alerts) == -1){
						logmsg(LOG_ERR, "[%s %i] Keywords error at word \"%s\" line %i file %s",
					   	    __FILE__, __LINE__, a_str_flag, line, file);
						exit(1);
					}
					str_flag = a_str_flag;
					buf++;
				}
				if(count >= 19){
					a_str_flag[19] = 0;
					logmsg(LOG_ERR, "[%s %i] Keywords error at word \"%s\" line %i file %s",
					       __FILE__, __LINE__, a_str_flag, line, file);
					exit(1);
				}
				*str_flag = *buf;
				str_flag++;
				count++;
				buf++;
				continue;
			}
	
		}
		// set read buffer et the beginig
		buf = a_buf;
	}
	close(fp);
}

void maclist_reload(void){
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Reload maclist", __FILE__, __LINE__);
	#endif
	data_reset();
	maclist_load();
}
