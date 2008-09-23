#include <pcap.h>
#include <pcap-bpf.h>
#include <stdlib.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <string.h>
#include "capture.h"
#include "log.h"
#include "loadconfig.h"
#include "data.h"
#include "config.h"
#include "alerte.h"

#define SNAP_LEN 1514
#define FILTER "arp or rarp"

int seq = 0;
int abus = 50;
int base = 22;

void callback(u_char *, const struct pcap_pkthdr *, const u_char *);

void cap_snif(void){
	char err[PCAP_ERRBUF_SIZE];
	char *device;
	pcap_t *idcap;
	bpf_u_int32 netp, maskp;
	struct bpf_program bp;
	
	/* recherche le premier device deisponoible */
	device = NULL;

	if(config[CF_IF].valeur.string[0] != 0){
		device = config[CF_IF].valeur.string;
	}
	
	if(device == NULL){
		if((device = pcap_lookupdev(err))==NULL){
			logmsg(LOG_ERR, "[%s %i] pcap_lookupdev: %s", __FILE__, __LINE__, err);
			exit(-1);
		}
		logmsg(LOG_NOTICE, "[%s %i] Auto selected device: %s", __FILE__, __LINE__, device);
	}

	if(strncmp(device, "all", 5)==0){
		device=NULL;
	}

	/* initialise l'interface */
	if((idcap = pcap_open_live(device, SNAP_LEN, 0, 0, err)) == NULL){
		logmsg(LOG_ERR, "[%s %i] pcap_open_live error: %s", __FILE__, __LINE__, err);
		exit(1);
	}

	/* recupere les parametre de l'interface */
	if (pcap_lookupnet(device, &netp, &maskp, err) < 0) {
		logmsg(LOG_ERR, "[%s %i] pcap_lookupnet error: %s", __FILE__, __LINE__, err);
		exit(1);
	}

	logmsg(LOG_DEBUG, "[%s %i] pcap link type:  %s", __FILE__, __LINE__, pcap_datalink_val_to_name(pcap_datalink(idcap)));
	switch(pcap_datalink(idcap)){
		case DLT_EN10MB:
			base = 22;
			break;

		case DLT_LINUX_SLL:
			base = 24;
			break;

		default:
			base = 22;
			break;
	}
	
	/* initilise le filtre: */
	if(pcap_compile(idcap, &bp, FILTER, 0x100, maskp) < 0){
		logmsg(LOG_ERR, "[%s %i] pcap_compile error: %s", __FILE__, __LINE__, pcap_geterr(idcap));
		exit(1);
	}

	/* appliquer le filtre: */
	if(pcap_setfilter(idcap, &bp)<0){
		logmsg(LOG_ERR, "[%s %i] pcap_setfilter error: %s", __FILE__, __LINE__, pcap_geterr(idcap));
		exit(1);
	}
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] pcap_setfilter [%s]: ok", __FILE__, __LINE__, FILTER);
	#endif

	if(pcap_loop(idcap, 0, callback, NULL) <0){
		logmsg(LOG_ERR, "[%s %i] pcap_loop error: %s", __FILE__, __LINE__, pcap_geterr(idcap));
		exit(1);
	}
}

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *buff){
	data_mac macs;
	unsigned char smacs[18];
	unsigned char ip[16];
	data_pack *data;
	data_ip ip_32;
	int ret;

	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Capture packet", __FILE__, __LINE__);
	#endif

	macs.octet[0] = buff[base + 0];
	macs.octet[1] = buff[base + 1];
	macs.octet[2] = buff[base + 2];
	macs.octet[3] = buff[base + 3];
	macs.octet[4] = buff[base + 4];
	macs.octet[5] = buff[base + 5];
	ip_32.bytes[0] = buff[base + 6];
	ip_32.bytes[1] = buff[base + 7];
	ip_32.bytes[2] = buff[base + 8];
	ip_32.bytes[3] = buff[base + 9];
		
	data_tomac(macs, smacs);
	snprintf((char *)ip, 16, "%u.%u.%u.%u", ip_32.bytes[0], ip_32.bytes[1], ip_32.bytes[2], ip_32.bytes[3]);

	data = data_exist(&macs);

	seq++;
	
	abus--;
	if(abus==0){
		logmsg(LOG_NOTICE, "Abnormal network ARP requests");
	}
	
	/* si pas d'adresse identifiée */
	if(data == NULL){
		if(config[CF_LOGNEW].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, type=new", seq, smacs, ip);
		}

		if(config[CF_ALRNEW].valeur.integer == TRUE){
			ret = alerte(smacs, ip, 3);
			#ifdef DEBUG
			if(ret > 0){
				logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i", __FILE__, __LINE__, ret);
			}
			#endif
		}
		
		data_add(&macs, APPEND, ip_32.ip);
		flagdump = TRUE;
		return;
	}
	
	/* test ip */
	if(data[0].ip.ip != ip_32.ip){
		if(config[CF_LOGIP].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s reference=%u.%u.%u.%u type=ip_change)",
				seq, smacs, ip, ip_32.bytes[0], ip_32.bytes[1], ip_32.bytes[2], ip_32.bytes[3]);
		}
		
		if(config[CF_ALRIP].valeur.integer == TRUE){
			ret = alerte(smacs, ip, 0); 
			#ifdef DEBUG
			if(ret > 0){
				logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i", __FILE__, __LINE__, ret);
			}
			#endif
		}
	}
	
	/* si entrée ajoutée mais non reference */
	if(data[0].flag == APPEND){
		if(config[CF_LOGALLOW].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d mac=%s, ip=%s, type=unknow_address", seq, smacs, ip);
		}

		if(config[CF_ALRALLOW].valeur.integer == TRUE){
			ret = alerte(smacs, ip, 1); 
			#ifdef DEBUG
			if(ret > 0){
				logmsg(LOG_DEBUG, "[%s %i] Forked with pid %i", __FILE__, __LINE__, ret);
			}
			#endif
		}
		return;
	}
	
	/* si entree interdite */
	if(data[0].flag == DENY){
		if(config[CF_LOGDENY].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, type=black_listed", seq, smacs, ip);
		}

		if(config[CF_ALRDENY].valeur.integer == TRUE){
			ret = alerte(smacs, ip, 2); 
			#ifdef DEBUG
			if(ret > 0){
				logmsg(LOG_DEBUG, "[%s %i] Forked with pid %i", __FILE__, __LINE__, ret);
			}
			#endif
		}
		return;
	}
	
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Mac sender %s ok", __FILE__, __LINE__, smacs);
	logmsg(LOG_DEBUG, "[%s %i] Capture ended", __FILE__, __LINE__);
	#endif
}

void cap_abus(void){
	abus = config[CF_ABUS].valeur.integer + 1;
}

