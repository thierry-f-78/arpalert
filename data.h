/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: data.h 124 2006-05-10 21:46:12Z thierry $
 *
 */

#ifndef __DATA_H
#define __DATA_H

#define NOT_EXIST 0
#define ALLOW     1
#define DENY      2
#define APPEND    4

#define IP_CHANGE            0
#define UNKNOWN_ADDRESS      1 
#define BLACK_LISTED         2
#define NEW                  3
#define UNAUTH_RQ            4
#define RQ_ABUS              5
#define MAC_ERROR            6 
#define FLOOD                7 
#define NEW_MAC              8
#define MAC_CHANGE           9

/* defini une adresse mac */
typedef struct {
	unsigned char octet[6];
} data_mac;

/* defini une adresse ip */
typedef union {
	u_int32_t ip;
	unsigned char bytes[4];
} data_ip;

typedef struct {
	data_mac mac;
	int flag;               /*0: @ok 1: @alert 2: new */
	data_ip ip;
	int timestamp;
	int lastalert[7];
	int request;
	u_int32_t alerts;			/* bit field used for set detect exception */
} data_pack;

// set ip_change              0: 1st bit
#define SET_IP_CHANGE(a)      a  |= 0x00000001
#define ISSET_IP_CHANGE(a)    (((a & 0x00000001) != 0)?TRUE:FALSE)
// set black_listed           2: 3rd bit
#define SET_BLACK_LISTED(a)   a  |= 0x00000004
#define ISSET_BLACK_LISTED(a) (((a & 0x00000004) != 0)?TRUE:FALSE)
// set unauthorized_request   4: 5th bit
#define SET_UNAUTH_RQ(a)      a  |= 0x00000010
#define ISSET_UNAUTH_RQ(a)    (((a & 0x00000010) != 0)?TRUE:FALSE)
// set rq_abus                5: 6th bit
#define SET_RQ_ABUS(a)        a  |= 0x00000050
#define ISSET_RQ_ABUS(a)      (((a & 0x00000050) != 0)?TRUE:FALSE)
// set mac_error              6: 7th bit
#define SET_MAC_ERROR(a)      a  |= 0x00000040
#define ISSET_MAC_ERROR(a)    (((a & 0x00000040) != 0)?TRUE:FALSE)
// set mac_change             9: 10th bit
#define SET_MAC_CHANGE(a)     a  |= 0x00000200
#define ISSET_MAC_CHANGE(a)   (((a & 0x00000200) != 0)?TRUE:FALSE)

// initialize data system
void data_init(void);

// clear all datas
void data_reset(void);

// dump all datas in file
void data_dump(void);

// clean all too old datas
void data_clean(int);

// compare 2 mac adresses
// return 0 if mac are equals
// data_cmp(data_mac *, data_mac *)
#define data_cmp(a, b) memcmp(a, b, sizeof(data_mac))

// copy mac
#define data_cpy(a, b) memcpy(a, b, sizeof(data_mac))

// add data to database with field
void data_add_field(data_mac *, int, int, u_int32_t);

// add data to database
data_pack *data_add(data_mac *, int, int);

// to change ip in data structur
//void change_ip(data_pack *, u_int32_t);

// force ip indexation
void index_ip(data_pack *);

// delete ip indexation
void unindex_ip(u_int32_t);
		  
// check if data exist
// return NULL if not exist
data_pack *data_exist(data_mac *);

// check if ip exist
// return NULL if not exist
data_pack *data_ip_exist(u_int32_t);

// translate binary data mac to string data mac
// void data_tomac(data_mac, char *);
#define MAC_TO_STR(a, b) sprintf(b, "%02x:%02x:%02x:%02x:%02x:%02x", \
                                 a.octet[0], a.octet[1], a.octet[2], \
                                 a.octet[3], a.octet[4], a.octet[5])

// translate string data mac to binary data mac
void str_to_mac(char *, data_mac *);

// translate string ip to binary ip
u_int32_t str_to_ip(char *);

// translate binary ip to string ip
// void ip_to_str(char *, data_ip)
#define IP_TO_STR(a, b) sprintf(b, "%u.%u.%u.%u", \
                                a.bytes[3], a.bytes[2], \
                                a.bytes[1], a.bytes[0]);
#endif
