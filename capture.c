#include <pcap.h>
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

pcap_t *idcap;
bpf_u_int32 netp, maskp;
struct bpf_program bp;
int seq = 1;
int abus = 50;

void callback(u_char *, const struct pcap_pkthdr *, const u_char *);

void cap_init(void){
	char err[PCAP_ERRBUF_SIZE];
	char *device;
	
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
}


void cap_snif(void){
	if(pcap_loop(idcap, 0, callback, NULL) <0){
		logmsg(LOG_ERR, "[%s %i] pcap_loop error: %s", __FILE__, __LINE__, pcap_geterr(idcap));
		exit(1);
	}
}

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *buff){
	data_mac macs;
	unsigned char smacs[18];
	unsigned char ip[16];
	struct ether_header *eh;
	struct ether_arp *ea;
	data_pack *data;
	data_ip ip_32;
	int i, ret;

	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Capture packet", __FILE__, __LINE__);
	#endif

	eh = (struct ether_header *)buff;
	ea = (struct ether_arp *)(eh + 1);
	i=-1;
	while(i++<5) macs.octet[i] = ea->arp_sha[i];
	
	data_tomac(macs, smacs);
	ip_32.bytes[0] = ea->arp_spa[0];
	ip_32.bytes[1] = ea->arp_spa[1];
	ip_32.bytes[2] = ea->arp_spa[2];
	ip_32.bytes[3] = ea->arp_spa[3];
	
	snprintf((char *)ip, 16, "%u.%u.%u.%u", ea->arp_spa[0], ea->arp_spa[1], ea->arp_spa[2], ea->arp_spa[3]);

	data = data_exist(&macs);

	seq++;
	
	abus--;
	if(abus==0){
		/*snprintf(msg, 1024, "SEQ:%i, ILLEGAL: MAC:%s, IP:%s (non reference)\n", seq, smacs, ip);*/
		logmsg(LOG_NOTICE, "[%s %i] Abnormal network ARP requests", __FILE__, __LINE__);
	}
	
	/* si pas d'adresse identifiée */
	if(data == NULL){
		if(config[CF_LOGNEW].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "ILLEGAL: MAC:%s, IP:%s (unreferenced)", smacs, ip);
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
			logmsg(LOG_NOTICE, "ILLEGAL: MAC:%s, IP:%s REFERENCE:%i.%i.%i.%i (ip change)", smacs, ip, (*data).ip.bytes[0], (*data).ip.bytes[1], (*data).ip.bytes[2], (*data).ip.bytes[3]);
		}
		
		if(config[CF_ALRIP].valeur.integer == TRUE){
			ret = alerte(smacs, ip, 0); 
			#ifdef DEBUG
			if(ret > 0){
				logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i", ret);
			}
			#endif
		}
	}
	
	/* si entrée ajoutée mai non reference */
	if(data[0].flag == APPEND){
		if(config[CF_LOGALLOW].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "ILLEGAL: MAC:%s, IP:%s (unreferenced but already detected)", smacs, ip);
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
			logmsg(LOG_NOTICE, "ILLEGAL: MAC:%s, IP:%s (referencced in black list)", smacs, ip);
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

