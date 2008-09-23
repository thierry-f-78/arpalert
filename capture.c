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
#include "sens.h"
#include "log.h"
#include "loadconfig.h"
#include "data.h"
#include "config.h"
#include "alerte.h"

#define SNAP_LEN 1514
/*
#define FILTER "arp or rarp"
#define FILTER "arp or ether src ff:ff:ff:ff:ff:ff"
*/
#define FILTER ""

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
 
	logmsg(LOG_DEBUG, "[%s %i] pcap link type:  %s", __FILE__, __LINE__,
		pcap_datalink_val_to_name(pcap_datalink(idcap)));
	switch(pcap_datalink(idcap)){
		case DLT_EN10MB:
			base = 21;
			break;

		case DLT_LINUX_SLL:
			base = 23;
			break;

		default:
			base = 21;
			break;
	}
	
	/* initilise le filtre: */
	if(pcap_compile(idcap, &bp, FILTER, 0x100, maskp) < 0){
		logmsg(LOG_ERR, "[%s %i] pcap_compile error: %s", __FILE__, __LINE__, pcap_geterr(idcap));
		exit(1);
	}

	/* appliquer le filtre: */
	if(pcap_setfilter(idcap, &bp)<0){
		logmsg(LOG_ERR, "[%s %i] pcap_setfilter error: %s",
			__FILE__, __LINE__, pcap_geterr(idcap));
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
	unsigned char smacs[18];
	unsigned char smacseth[18];
	unsigned char ip[16];
	unsigned char iq[16];
	unsigned char ip_tmp[16];
	data_pack *data;
	data_pack *dataeth;
	data_mac macs;
	data_mac maceth;
	data_ip ip_32;
	data_ip ip_33;
	data_ip broadcast;
	int ret, flag;
	int timeact;
	int i;

	smacs[0]=0;
	smacseth[0]=0;
	strcpy((char *)&ip, "0.0.0.0");
	strcpy((char *)&iq, "0.0.0.0");
	ip_32.ip=0;
	ip_33.ip=0;
	timeact=time(NULL);
	
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Capture packet", __FILE__, __LINE__);
	#endif

	if(config[CF_DUMP_PAQUET].valeur.integer == TRUE){
		for(i=0; i<53; i++){
			if(i%6==0) printf("\n%2d: ", i);
			 printf("%02x ", buff[i]);
		}
		printf("\n");
	}

	/* get a ethernet mac source */
	maceth.octet[0] = buff[6];
	maceth.octet[1] = buff[7];
	maceth.octet[2] = buff[8];
	maceth.octet[3] = buff[9];
	maceth.octet[4] = buff[10];
	maceth.octet[5] = buff[11];
	
	dataeth = data_exist(&maceth);
	data_tomac(maceth, smacseth);

	seq++;

	/* is an arp who-has ? */
	if(buff[base + 0] == 1 && buff[12] == 8 && buff[13] == 6) {
	
		/* mac du poseur de question */
		macs.octet[0] = buff[base + 1];
		macs.octet[1] = buff[base + 2];
		macs.octet[2] = buff[base + 3];
		macs.octet[3] = buff[base + 4];
		macs.octet[4] = buff[base + 5];
		macs.octet[5] = buff[base + 6];

		/* ip du questionneur */
		ip_32.bytes[0] = buff[base + 7];
		ip_32.bytes[1] = buff[base + 8];
		ip_32.bytes[2] = buff[base + 9];
		ip_32.bytes[3] = buff[base + 10];
		
		/* ip du questionné */
		ip_33.bytes[0] = buff[base + 17];
		ip_33.bytes[1] = buff[base + 18];
		ip_33.bytes[2] = buff[base + 19];
		ip_33.bytes[3] = buff[base + 20];

		data = data_exist(&macs);
		data_tomac(macs, smacs);
		
		snprintf((char *)ip, 16, "%u.%u.%u.%u", 
			ip_32.bytes[0], ip_32.bytes[1], ip_32.bytes[2], ip_32.bytes[3]);
		snprintf((char *)iq, 16, "%u.%u.%u.%u", 
			ip_33.bytes[0], ip_33.bytes[1], ip_33.bytes[2], ip_33.bytes[3]);
		
		/****************************************************
		 * begin of arp dependant traitments 
		 ****************************************************/
		
		/* non authorized request */
		if(config[CF_AUTHFILE].valeur.string[0]!=0){
			broadcast.bytes[0] = 255;
			broadcast.bytes[1] = 255;
			broadcast.bytes[2] = 255;
			broadcast.bytes[3] = 255;
			flag=TRUE;
			if(config[CF_IGNORE_UNKNOW].valeur.integer == TRUE){
				if(data == NULL){
					flag=FALSE;
				}else{
					if(data[0].flag != ALLOW){
						flag=FALSE;
					}
				}
			}
			
			if(sens_exist(&macs, broadcast)==FALSE && flag==TRUE){
				if(sens_exist(&macs, ip_33)==FALSE){
					if(config[CF_LOG_UNAUTH_RQ].valeur.integer == TRUE){
						logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, rq=%s, type=unauthrq", 
						       seq, smacs, ip, iq);
					}
					if(config[CF_ALERT_UNAUTH_RQ].valeur.integer == TRUE){
						ret = alerte(smacs, ip, iq, 4);
						#ifdef DEBUG
						if(ret > 0){
							logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i",
								__FILE__, __LINE__, ret);
						}
						#endif
					}
				}
			}
		}

		/* test ip change */
		if(data != NULL){
			if(data[0].ip.ip != ip_32.ip){
				if(data[0].ip.ip != 0 && ip_32.ip != 0){
					snprintf((char *)ip_tmp, 16, "%u.%u.%u.%u",
						data[0].ip.bytes[0], data[0].ip.bytes[1], 
						data[0].ip.bytes[2], data[0].ip.bytes[3]);
					if(config[CF_LOGIP].valeur.integer == TRUE){
						logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, reference=%s, type=ip_change",
							seq, smacs, ip, ip_tmp); 
					}
				
					if(config[CF_ALRIP].valeur.integer == TRUE){
						ret = alerte(smacseth, ip, ip_tmp, 0); 
						#ifdef DEBUG
						if(ret > 0){
							logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i",
								__FILE__, __LINE__, ret);
						}
						#endif
					}
				}
				data[0].ip.ip = ip_32.ip;
				flagdump = TRUE;
			}
		}

		/* error with ethernet mac and arp mac*/
		if(macs.octet[0]!=maceth.octet[0] || \
		   macs.octet[1]!=maceth.octet[1] || \
		   macs.octet[2]!=maceth.octet[2] || \
		   macs.octet[3]!=maceth.octet[3] || \
		   macs.octet[4]!=maceth.octet[4] || \
		   macs.octet[5]!=maceth.octet[5]){
			if(config[CF_LOG_BOGON].valeur.integer == TRUE){
				logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, reference=%s, type=mac_error",
				seq, smacseth, ip, smacs);
			}

			if(config[CF_ALR_BOGON].valeur.integer == TRUE){
				ret = alerte(smacseth, ip, smacs, 6);
				#ifdef DEBUG
				if(ret > 0){
					logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i",
						__FILE__, __LINE__, ret);
				}
				#endif
			}
		}

		/* excessive request */
		if(dataeth!=NULL){
			if(dataeth[0].timestamp == timeact){
				dataeth[0].request++;
				if(dataeth[0].request == config[CF_ABUS].valeur.integer + 1){
					if(config[CF_LOG_ABUS].valeur.integer == TRUE){
						logmsg(LOG_NOTICE, "sec=%d, mac=%s, ip=%s, type=rqabus", 
							seq, smacseth, ip);
					}

					if(config[CF_ALERT_ABUS].valeur.integer == TRUE){
						ret = alerte(smacseth, ip, "", 5);
						#ifdef DEBUG
						if(ret > 0){
							logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i", __FILE__, __LINE__, ret);
						}
						#endif
					}
				}
			} else {
				dataeth[0].timestamp = timeact;
				dataeth[0].request = 0;
			}
		}
		/****************************************************
		 * end of arp dependant traitments 
		 ****************************************************/
	}
	
	/* si pas d'adresse identifiée */
	if(dataeth == NULL){
		if(config[CF_LOGNEW].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, type=new", seq, smacseth, ip);
		}

		if(config[CF_ALRNEW].valeur.integer == TRUE){
			ret = alerte(smacseth, ip, "", 3);
			#ifdef DEBUG
			if(ret > 0){
				logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i", __FILE__, __LINE__, ret);
			}
			#endif
		}
		
		data_add(&maceth, APPEND, ip_32.ip);
		flagdump = TRUE;
	}
	
	/* si entrée ajoutée mais non reference */
	if(dataeth != NULL){
		if(dataeth[0].flag == APPEND){
			if(config[CF_LOGALLOW].valeur.integer == TRUE){
				logmsg(LOG_NOTICE, "seq=%d mac=%s, ip=%s, type=unknow_address", 
					seq, smacseth, ip);
			}

			if(config[CF_ALRALLOW].valeur.integer == TRUE){
				ret = alerte(smacseth, ip, "", 1); 
				#ifdef DEBUG
				if(ret > 0){
					logmsg(LOG_DEBUG, "[%s %i] Forked with pid %i", __FILE__, __LINE__, ret);
				}
				#endif
			}
		}
	}
	
	/* si entree interdite */
	if(dataeth != NULL){
		if(dataeth[0].flag == DENY){
			if(config[CF_LOGDENY].valeur.integer == TRUE){
				logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, type=black_listed", seq, smacseth, ip);
			}

			if(config[CF_ALRDENY].valeur.integer == TRUE){
				ret = alerte(smacseth, ip, "", 2); 
				#ifdef DEBUG
				if(ret > 0){
					logmsg(LOG_DEBUG, "[%s %i] Forked with pid %i", __FILE__, __LINE__, ret);
				}
				#endif
			}
		}
		
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %i] Mac sender %s ok", __FILE__, __LINE__, smacs);
		logmsg(LOG_DEBUG, "[%s %i] Capture ended", __FILE__, __LINE__);
		#endif
	}
}

void cap_abus(void){
	abus = config[CF_ABUS].valeur.integer + 1;
}

