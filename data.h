#define NOT_EXIST 0
#define ALLOW 1
#define DENY 2
#define APPEND 3

#ifndef __DATA_H
#define __DATA_H 1

/* defini une adresse mac */
typedef struct {
	unsigned char octet[6];
} data_mac;

/* defini une adresse ip */
typedef union {
	unsigned char bytes[4];
	int ip;
} data_ip;

typedef struct {
	data_mac mac;
	int flag;               /*0: @ok 1: @alert 2: new */
	data_ip ip;
	int timestamp;
	int lastalert[7];
	int request;
} data_pack;
				      

void data_init(void);
void data_reset(void);
void data_close(void);
void data_dump(void);
void data_clean(int);
void data_add(data_mac *, int, int);
data_pack *data_exist(data_mac *);
void data_tomac(data_mac, unsigned char *);
void data_tohex(unsigned char *, data_mac *);
int data_toip(unsigned char *);

#endif
