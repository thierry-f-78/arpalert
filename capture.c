#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <grp.h>
#include <stdio.h>

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>

#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <net/if_dl.h>
#endif

#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

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
int base = 21;
int count = 0;
int count_t = 0;
data_mac me;
pcap_t *idcap;

void callback(u_char *, const struct pcap_pkthdr *, const u_char *);

void cap_init(void){
	char err[PCAP_ERRBUF_SIZE];
	char *device;
	char ethernet[18];
	char filtre[1024];
	struct bpf_program bp;
	int promisc;

	#if defined(__linux__)
	int sock_fd;
	struct ifreq ifr;
	#endif

	#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__)
	int mib[6], len;
	char *buf;
	unsigned char *ptr;
	struct if_msghdr *ifm;
	struct sockaddr_dl *sdl;
	#endif

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

	/* fiond my arp adresses */
	strncpy(filtre, FILTER, 1024);

	if(config[CF_IGNORE_ME].valeur.integer == TRUE){
		#if defined(__linux__)
		if((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ){
			logmsg(LOG_ERR, "[%s %i] Error in socket creation", __FILE__, __LINE__);
			exit(1);
		}
		memset(&ifr, 0, sizeof(ifr));
		strncpy (ifr.ifr_name, device, sizeof(ifr.ifr_name));
		if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) == -1 ) {
			logmsg(LOG_ERR, "[%s %i] Error in ioctl call", __FILE__, __LINE__);
			exit(1);
		}
		me.octet[0] = ifr.ifr_addr.sa_data[0];
		me.octet[1] = ifr.ifr_addr.sa_data[1];
		me.octet[2] = ifr.ifr_addr.sa_data[2];
		me.octet[3] = ifr.ifr_addr.sa_data[3];
		me.octet[4] = ifr.ifr_addr.sa_data[4];
		me.octet[5] = ifr.ifr_addr.sa_data[5];
		#endif

		#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__)
		mib[0] = CTL_NET;
		mib[1] = AF_ROUTE;
		mib[2] = 0;
		mib[3] = AF_LINK;
		mib[4] = NET_RT_IFLIST;
		if ((mib[5] = if_nametoindex(device)) == 0) {
			logmsg(LOG_ERR, "[%s %i] if_nametoindex error", __FILE__, __LINE__);
			exit(1);
		}
		if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
			logmsg(LOG_ERR, "[%s %i] sysctl 1 error", __FILE__, __LINE__);
			exit(1);
		}
		if ((buf = malloc(len)) == NULL) {
			logmsg(LOG_ERR, "[%s %i] malloc error", __FILE__, __LINE__);
			exit(1);
		}
		if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
			logmsg(LOG_ERR, "[%s %i] sysctl 2 error", __FILE__, __LINE__);
			exit(1);
		}
		ifm = (struct if_msghdr *)buf;
		sdl = (struct sockaddr_dl *)(ifm + 1);
		ptr = (unsigned char *)LLADDR(sdl);
		me.octet[0] = *ptr;
		me.octet[1] = *(ptr+1);
		me.octet[2] = *(ptr+2);
		me.octet[3] = *(ptr+3);
		me.octet[4] = *(ptr+4);
		me.octet[5] = *(ptr+5);
		free(buf);
		#endif

		data_tomac(me, (unsigned char *)ethernet);
		strncat(filtre, " not ether host ", 1024);
		strncat(filtre, ethernet, 1024);
	}
	
	/* initialise l'interface */
	if(config[CF_PROMISC].valeur.integer==TRUE){
		promisc = 1;
	} else {
		promisc = 0;
	}
	if((idcap = pcap_open_live(device, SNAP_LEN, promisc, 0, err)) == NULL){
		logmsg(LOG_ERR, "[%s %i] pcap_open_live error: %s", __FILE__, __LINE__, err);
		exit(1);
	}

	if(pcap_datalink(idcap) != DLT_EN10MB){
		logmsg(LOG_ERR, "[%s %i] pcap_datalink errror: unrecognied link", __FILE__, __LINE__);
		exit(1);
	}
	
	/* initilise le filtre: */
	if(pcap_compile(idcap, &bp, filtre, 0x100, /*maskp*/ 0) < 0){
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
}

void cap_sniff(void){
	while(TRUE){
		if(pcap_loop(idcap, 0, callback, NULL)<0){
			logmsg(LOG_ERR, "[%s %i] pcap_loop error: %s (trying to reconnect)", 
				__FILE__, __LINE__, pcap_geterr(idcap));
		}
	}
	exit(1);
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

	broadcast.bytes[0] = 255;
	broadcast.bytes[1] = 255;
	broadcast.bytes[2] = 255;
	broadcast.bytes[3] = 255;
	smacs[0]=0;
	smacseth[0]=0;
	strcpy((char *)&ip, "0.0.0.0");
	strcpy((char *)&iq, "0.0.0.0");
	ip_32.ip=0;
	ip_33.ip=0;
	timeact=time(NULL);
	
	if(count > config[CF_ANTIFLOOD_GLOBAL].valeur.integer \
		&& timeact - count_t < config[CF_ANTIFLOOD_INTER].valeur.integer) {
		return;
	}
	
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
	
		/* general flood detection */
		if(count_t == timeact){
			count ++;
			#ifdef DEBUG
			logmsg(LOG_DEBUG, "count=%d", count);
			#endif
		} else {
			count = 1;
			count_t = timeact;
		}
		if(count > config[CF_ANTIFLOOD_GLOBAL].valeur.integer) {
			if(config[CF_LOG_FLOOD].valeur.integer == TRUE){
				logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, rq=%s, type=flood",
				       seq, smacs, ip, iq);
			}
			if(config[CF_ALERT_ON_FLOOD].valeur.integer == TRUE){
				ret = alerte(smacs, ip, iq, 7);
				#ifdef DEBUG
				if(ret > 0){
					logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i",
						__FILE__, __LINE__, ret);
				}
				#endif
			}
			return;
		}
		
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
			flag=TRUE;
			if(config[CF_IGNORE_UNKNOW].valeur.integer == TRUE){
				if(data == NULL){
					flag=FALSE;
				} else {
					if(data[0].flag != ALLOW){
						flag=FALSE;
					}
				}
			}
	
			if(data != NULL && config[CF_IGNORESELFTEST].valeur.integer == TRUE){
				if(data->ip.ip == ip_33.ip){
					flag = FALSE;
				}
			}
			
			if(dataeth != NULL){
				if(timeact - dataeth->lastalert[4] >= config[CF_ANTIFLOOD_INTER].valeur.integer){
					dataeth->lastalert[4] = timeact;
				} else {
					flag=FALSE;
				}
			}		
			
			/* if the mac adress is authorized: */
			if(sens_exist(&macs, broadcast) == TRUE){
				flag = FALSE;
			}
			
			if(flag==TRUE){
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
			#ifdef DEBUG
			logmsg(LOG_DEBUG, "[%s %i] test ip change: %d - %d > %d", 
				__FILE__, __LINE__, timeact, data->lastalert[0], config[CF_ANTIFLOOD_INTER].valeur.integer);
			#endif
			if(data[0].ip.ip != ip_32.ip
			&& data[0].ip.ip != broadcast.ip
			){
				if(data[0].ip.ip != 0 && ip_32.ip != 0){
					if(timeact - data->lastalert[0] >= config[CF_ANTIFLOOD_INTER].valeur.integer){
						data->lastalert[0] = timeact;
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
				} else if(data->ip.ip == 0 && ip_32.ip != 0) {
					if(config[CF_LOGNEW].valeur.integer == TRUE){
						logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, type=new", seq, smacseth, ip);
					}
			
					if(config[CF_ALRNEW].valeur.integer == TRUE){
						ret = alerte(smacseth, ip, (unsigned char *)"", 3);
						#ifdef DEBUG
						if(ret > 0){
							logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i", __FILE__, __LINE__, ret);
						}
						#endif
					}
					
					flagdump = TRUE;
				}
				data[0].ip.ip = ip_32.ip;
				flagdump = TRUE;
			}
		}

		/* error with ethernet mac and arp mac*/
		if(dataeth != NULL){
			if(timeact - dataeth->lastalert[6] >= config[CF_ANTIFLOOD_INTER].valeur.integer){
				dataeth->lastalert[6] = timeact;
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
			}
		}

		/* excessive request */
		if(dataeth!=NULL){
			if(dataeth[0].timestamp == timeact){
				dataeth[0].request++;
				if(dataeth[0].request == config[CF_ABUS].valeur.integer + 1){
					if(timeact - dataeth->lastalert[5] >= config[CF_ANTIFLOOD_INTER].valeur.integer){
						dataeth->lastalert[5] = timeact;
						if(config[CF_LOG_ABUS].valeur.integer == TRUE){
							logmsg(LOG_NOTICE, "sec=%d, mac=%s, ip=%s, type=rqabus", 
								seq, smacseth, ip);
						}
	
						if(config[CF_ALERT_ABUS].valeur.integer == TRUE){
							ret = alerte(smacseth, ip, (unsigned char *)"", 5);
							#ifdef DEBUG
							if(ret > 0){
								logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i", __FILE__, __LINE__, ret);
							}
							#endif
						}
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
		if(ip_32.ip==0){
			if(config[CF_LOGNEW].valeur.integer == TRUE){
				logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, type=new_mac", seq, smacseth, ip);
			}
	
			if(config[CF_ALRNEW].valeur.integer == TRUE){
				ret = alerte(smacseth, ip, (unsigned char *)"", 8);
				#ifdef DEBUG
				if(ret > 0){
					logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i", __FILE__, __LINE__, ret);
				}
				#endif
			}
			
			data_add(&maceth, APPEND, ip_32.ip);
			flagdump = TRUE;
		} else {
			if(config[CF_LOGNEW].valeur.integer == TRUE){
				logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, type=new", seq, smacseth, ip);
			}
	
			if(config[CF_ALRNEW].valeur.integer == TRUE){
				ret = alerte(smacseth, ip, (unsigned char *)"", 3);
				#ifdef DEBUG
				if(ret > 0){
					logmsg(LOG_DEBUG, "[%s %i] Forked with pid: %i", __FILE__, __LINE__, ret);
				}
				#endif
			}
			
			data_add(&maceth, APPEND, ip_32.ip);
			flagdump = TRUE;
		}
	}
	
	/* si entrée ajoutée mais non reference */
	if(dataeth != NULL){
		if(dataeth[0].flag == APPEND && 
		timeact - dataeth->lastalert[1] >= config[CF_ANTIFLOOD_INTER].valeur.integer){
			dataeth->lastalert[1] = timeact;
			if(config[CF_LOGALLOW].valeur.integer == TRUE){
				logmsg(LOG_NOTICE, "seq=%d mac=%s, ip=%s, type=unknow_address", 
					seq, smacseth, ip);
			}

			if(config[CF_ALRALLOW].valeur.integer == TRUE){
				ret = alerte(smacseth, ip, (unsigned char *)"", 1); 
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
		if(dataeth[0].flag == DENY &&
		timeact - dataeth->lastalert[2] >= config[CF_ANTIFLOOD_INTER].valeur.integer){
			dataeth->lastalert[2] = timeact;
			if(config[CF_LOGDENY].valeur.integer == TRUE){
				logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, type=black_listed", seq, smacseth, ip);
			}

			if(config[CF_ALRDENY].valeur.integer == TRUE){
				ret = alerte(smacseth, ip, (unsigned char *)"", 2); 
				#ifdef DEBUG
				if(ret > 0){
					logmsg(LOG_DEBUG, "[%s %i] Forked with pid %i", __FILE__, __LINE__, ret);
				}
				#endif
			}
		}
		
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %i] Capture ended", __FILE__, __LINE__);
		#endif
	}
}

void cap_abus(void){
	abus = config[CF_ABUS].valeur.integer + 1;
}

