/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: capture.c 89 2006-05-09 15:31:10Z thierry $
 *
 */

#include "config.h"

#include <pcap.h>
#include <stdlib.h>
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

#include "arpalert.h"
#include "capture.h"
#include "sens.h"
#include "log.h"
#include "loadconfig.h"
#include "data.h"
#include "alerte.h"
#include "sens_timeouts.h"


#define SNAP_LEN 1514
/*
#define FILTER "arp or rarp"
#define FILTER "arp or ether src ff:ff:ff:ff:ff:ff"
*/
#define FILTER_BASE ""
#define FILTER_EXCLUDE "not ether host "

// constantes
//const char mac_empty[]  = "00:00:00:00:00:00";
const data_mac null_mac = { { 0, 0, 0, 0, 0, 0 } };
//const char ip_empty[] = "0.0.0.0";
const data_ip broadcast = { 0xffffffff };

// persistent var
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
	char filtre[1024] = FILTER_BASE;
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

	// find first usable device
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

	// find my arp adresses for this device
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
		data_cpy(&me, &ifr.ifr_addr.sa_data);
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
		data_cpy(&me, ptr);
		free(buf);
		#endif

		strcat(filtre, FILTER_EXCLUDE);
		MAC_TO_STR(me, &filtre[strlen(filtre)]);
	}
	
	// promiscuous mode ?
	if(config[CF_PROMISC].valeur.integer==TRUE){
		promisc = 1;
	} else {
		promisc = 0;
	}
	
	// interface initialization 
	if((idcap = pcap_open_live(device, SNAP_LEN, promisc, 0, err)) == NULL){
		logmsg(LOG_ERR, "[%s %i] pcap_open_live error: %s",
		       __FILE__, __LINE__, err);
		exit(1);
	}

	if(pcap_datalink(idcap) != DLT_EN10MB){
		logmsg(LOG_ERR, "[%s %i] pcap_datalink errror: unrecognized link",
		       __FILE__, __LINE__);
		exit(1);
	}
	
	/* initilise le filtre: */
	if(pcap_compile(idcap, &bp, filtre, 0x100, /*maskp*/ 0) < 0){
		logmsg(LOG_ERR, "[%s %i] pcap_compile error: %s",
		       __FILE__, __LINE__, pcap_geterr(idcap));
		exit(1);
	}

	/* appliquer le filtre: */
	if(pcap_setfilter(idcap, &bp)<0){
		logmsg(LOG_ERR, "[%s %i] pcap_setfilter error: %s",
			__FILE__, __LINE__, pcap_geterr(idcap));
		exit(1);
	}
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] pcap_setfilter [%s]: ok",
	       __FILE__, __LINE__, filtre);
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

// convert eth mac source to string
#define STR_ETH_MAC_SENDER if(flag_str_eth_mac_sender == FALSE){ \
                           	MAC_TO_STR(eth_mac_sender[0], str_eth_mac_sender); \
                           	flag_str_eth_mac_sender = TRUE; \
                           }

// convert mac into sting
#define STR_ARP_MAC_SENDER if(flag_str_arp_mac_sender == FALSE){ \
                           	MAC_TO_STR(arp_mac_sender[0], str_arp_mac_sender); \
                           	flag_str_arp_mac_sender = TRUE;	\
                           }	

// convert ip into string
#define ARP_IP_SENDER if(flag_str_arp_ip_sender == FALSE){ \
                      	IP_TO_STR(arp_ip_sender, str_arp_ip_sender); \
                      	flag_str_arp_ip_sender = TRUE; \
                      }

// convert ip into string
#define ARP_IP_RCPT if(flag_str_arp_ip_rcpt == FALSE){ \
                    	IP_TO_STR(arp_ip_rcpt, str_arp_ip_rcpt); \
                    	flag_str_arp_ip_rcpt = TRUE; \
                    }

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *buff){
	char m_eth_mac_sender[18];
	char m_arp_mac_sender[18];
	char m_arp_ip_sender[16];
	char m_arp_ip_rcpt[16];

	int flag_is_arp = FALSE;
	data_mac *eth_mac_sender = (data_mac *)&null_mac;
	data_mac *arp_mac_sender = (data_mac *)&null_mac;
	data_ip arp_ip_sender = { 0x00000000 };
	data_ip arp_ip_rcpt   = { 0x00000000 };
	data_pack *eth_data = NULL;
	data_pack *ip_data = NULL;
	char *str_eth_mac_sender = m_eth_mac_sender;
	char *str_arp_mac_sender = m_arp_mac_sender;
	char *str_arp_ip_sender = m_arp_ip_sender;
	char *str_arp_ip_rcpt   = m_arp_ip_rcpt;
	int flag_str_eth_mac_sender = FALSE;
	int flag_str_arp_mac_sender = FALSE;
	int flag_str_arp_ip_sender = FALSE; 
	int flag_str_arp_ip_rcpt = FALSE;
	int flag_unknown_address = TRUE;

	char ip_tmp[16];
	char mac_tmp[18];
	int timeact;
	int i;

	// if dump paquet is active
	if(config[CF_DUMP_PAQUET].valeur.integer == TRUE){
		for(i=0; i<53; i++){
			if(i%6==0){
				printf("\n%2d: ", i);
			}
			printf("%02x ", buff[i]);
		}
		printf("\n");
	}

	// get the time
	timeact = h->ts.tv_sec;
	
	if(count > config[CF_ANTIFLOOD_GLOBAL].valeur.integer &&
	   timeact - count_t < config[CF_ANTIFLOOD_INTER].valeur.integer) {
		return;
	}
	
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] Capture packet", __FILE__, __LINE__);
	#endif

	//increment sequence
	seq++;

	// get a ethernet mac source
	eth_mac_sender = (data_mac *)&buff[6];

	// get properties memorised of this mac
	eth_data = data_exist(eth_mac_sender);

	if(eth_data != NULL) {
		flag_unknown_address = FALSE;
	}

	// is an arp who-has ?
	if(buff[base + 0] == 1 && buff[12] == 8 && buff[13] == 6) {
	
		// set flag "is arp"
		flag_is_arp = TRUE;
		
		// get arp mac sender
		arp_mac_sender = (data_mac *)&buff[base + 1];

		// get ip arp sender
		arp_ip_sender.bytes[3] = buff[base + 7];
		arp_ip_sender.bytes[2] = buff[base + 8];
		arp_ip_sender.bytes[1] = buff[base + 9];
		arp_ip_sender.bytes[0] = buff[base + 10];
		
		// get ip arp rcpt
		arp_ip_rcpt.bytes[3] = buff[base + 17];
		arp_ip_rcpt.bytes[2] = buff[base + 18];
		arp_ip_rcpt.bytes[1] = buff[base + 19];
		arp_ip_rcpt.bytes[0] = buff[base + 20];

		// count number of request in 1 second
		if(count_t == timeact){
			count ++;
		} else {
			count = 1;
			count_t = timeact;
		}
	}
	
	// =====================================
	// ARP general flood detection
	// =====================================
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %d] \"ARP general flood detection\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// is an arp request
		flag_is_arp == TRUE &&

		// global arp flood
		count > config[CF_ANTIFLOOD_GLOBAL].valeur.integer
	){
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %d] \"DETECTED", __FILE__, __LINE__);
		#endif

		STR_ETH_MAC_SENDER
		ARP_IP_SENDER
		ARP_IP_RCPT
		
		if(config[CF_LOG_FLOOD].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, rq=%s, type=flood",
			       seq, str_eth_mac_sender, str_arp_ip_sender, str_arp_ip_rcpt);
		}
		if(config[CF_ALERT_ON_FLOOD].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, str_arp_ip_rcpt, 7);
		}
		return;
	}
		
	// =====================================
	//  New mac adress detection
	// =====================================
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %d] \"New mac adress detection\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// mac adress inconue
		eth_data == NULL && 

		// ip unknown
		arp_ip_sender.ip == 0
	) {
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %d] \"DETECTED", __FILE__, __LINE__);
		#endif
		
		// add data to database
		eth_data = data_add(eth_mac_sender, APPEND, arp_ip_sender.ip);

		// allow to dump data
		flagdump = TRUE;

		STR_ETH_MAC_SENDER
		ARP_IP_SENDER
		
		if(config[CF_LOGNEWMAC].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, type=new_mac",
			       seq, str_eth_mac_sender, str_arp_ip_sender);
		}
		if(config[CF_ALRNEWMAC].valeur.integer == TRUE){	
			alerte(str_eth_mac_sender, str_arp_ip_sender, "", 8);
		}
	}

	// =====================================
	//  New mac adress and ip detection
	// =====================================
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %d] \"New mac adress and ip detection\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if (
		// ip known
		arp_ip_sender.ip != 0 &&
		
		(
			// mac adress inconue
			eth_data == NULL ||

			// ip inconue
			eth_data->ip.ip == 0
		)
	) {
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %d] DETECTED", __FILE__, __LINE__);
		#endif
		
		// add data to database
		if(eth_data == NULL) {
			eth_data = data_add(eth_mac_sender, APPEND, arp_ip_sender.ip);
		} else {
			eth_data->ip.ip = arp_ip_sender.ip;
			index_ip(eth_data);
		}
			
		// allow to dump data
		flagdump = TRUE;

		STR_ETH_MAC_SENDER
		ARP_IP_SENDER

		if(config[CF_LOGNEW].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, type=new",
			       seq, str_eth_mac_sender, str_arp_ip_sender);
		}
		if(config[CF_ALRNEW].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, "", 3);
		}
	}
	
	// =====================================
	// test mac change
	// =====================================
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %d] \"test mac change\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// check if this alert is configured
		(
			config[CF_ALERT_MACCHG].valeur.integer == TRUE ||
			config[CF_LOG_MACCHG].valeur.integer == TRUE
		) &&

		// sender is known
		arp_ip_sender.ip != 0 &&

		// sender exist
		(ip_data = data_ip_exist(arp_ip_sender.ip)) != NULL &&

		// if the bitfield is not active
		ISSET_MAC_CHANGE(eth_data->alerts) == FALSE &&
		
		// have different mac address
		//data_cmp(&ip_data->mac.octet[0], eth_mac_sender) != 0
		ip_data != eth_data
	){
		// maj ip in database
		unindex_ip(arp_ip_sender.ip);
		eth_data->ip.ip = arp_ip_sender.ip;
		index_ip(eth_data);

		// can dump database
		flagdump = TRUE;
	
		STR_ETH_MAC_SENDER
		ARP_IP_SENDER
		MAC_TO_STR(ip_data->mac, mac_tmp);

		if(config[CF_LOG_MACCHG].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, reference=%s, type=mac_change",
			       seq, str_eth_mac_sender, str_arp_ip_sender, mac_tmp);
		}
		if(config[CF_ALERT_MACCHG].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, "", 9);
		}
	}

	// =====================================
	// test ip change
	// =====================================
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %d] \"test ip change\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// if ip known different than ip detected
		eth_data->ip.ip != arp_ip_sender.ip &&

		// if ip known differnent then a broadcast
		// ( protect aliases )
		eth_data->ip.ip != broadcast.ip &&
			
		// if ip known different than a nul adress
		// (mac already detected but whitout ip)
		eth_data->ip.ip != 0 &&

		// ip detected different than null adress
		arp_ip_sender.ip != 0 &&
			
		// if the bitfield is not active
		ISSET_IP_CHANGE(eth_data->alerts) == FALSE &&
		
		// check timeouts
		timeact - eth_data->lastalert[0] >= config[CF_ANTIFLOOD_INTER].valeur.integer
	){
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %d] \"DETECTED", __FILE__, __LINE__);
		#endif
		
		// maj timeout
		eth_data->lastalert[0] = timeact;
					
		// maj database
		eth_data->ip.ip = arp_ip_sender.ip;
		index_ip(eth_data);

		// can dump database
		flagdump = TRUE;
	
		// convert ip to string
		IP_TO_STR(eth_data->ip, ip_tmp);
		STR_ETH_MAC_SENDER
		ARP_IP_SENDER
	
		if(config[CF_LOGIP].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, reference=%s, type=ip_change",
			       seq, str_eth_mac_sender, str_arp_ip_sender, ip_tmp); 
		}	
		if(config[CF_ALRIP].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, ip_tmp, 0); 
		}
	}

	// =====================================
	// non authorized request
	// =====================================
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %d] \"non authorized request\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// check if loggued
		config[CF_LOG_UNAUTH_RQ].valeur.integer + config[CF_ALERT_UNAUTH_RQ].valeur.integer != FALSE &&
		
		// is an arp request
		flag_is_arp == TRUE &&

		// the authfile do not complited
		config[CF_AUTHFILE].valeur.string[0] != 0 &&
		
		// if the bitfield is not active
		ISSET_UNAUTH_RQ(eth_data->alerts) == FALSE &&
		
		(
			// permit to ignore acl for not referenced machines
			config[CF_IGNORE_UNKNOWN].valeur.integer == FALSE ||
			eth_data->flag == ALLOW
		) &&
			
		(
			// permit to ignore arp self test
			config[CF_IGNORESELFTEST].valeur.integer == FALSE ||
			eth_data->ip.ip != arp_ip_rcpt.ip
		) &&

		(
			// normal flood control 
			config[CF_UNAUTH_TO_METHOD].valeur.integer != 1 ||
			timeact - eth_data->lastalert[4] >= config[CF_ANTIFLOOD_INTER].valeur.integer
		) &&
		
		(
			// flood control by tuple (mac / ip)
			config[CF_UNAUTH_TO_METHOD].valeur.integer != 2 ||
			sens_timeout_exist(eth_mac_sender, arp_ip_rcpt) == FALSE
		) &&
			
		// check if request is authorized
		sens_exist(eth_mac_sender, arp_ip_rcpt) == FALSE

	){
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %d] \"DETECTED", __FILE__, __LINE__);
		#endif
		
		// add info for advanced timeouts 
		if(config[CF_UNAUTH_TO_METHOD].valeur.integer == 2 &&
		   config[CF_ANTIFLOOD_INTER].valeur.integer != 0){
			sens_timeout_add(eth_mac_sender, arp_ip_rcpt);
		}

		// add info for simple timeout
		eth_data->lastalert[4] = timeact;

		STR_ETH_MAC_SENDER
		ARP_IP_SENDER
		ARP_IP_RCPT

		// ALERT
		if(config[CF_LOG_UNAUTH_RQ].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, rq=%s, type=unauthrq", 
			       seq, str_eth_mac_sender, str_arp_ip_sender, str_arp_ip_rcpt);
		}
		if(config[CF_ALERT_UNAUTH_RQ].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, str_arp_ip_rcpt, 4);
		}
	}

	// =====================================
	// error with ethernet mac and arp mac
	// =====================================
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %d] \"error with ethernet mac and arp mac\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// check if loggued
		config[CF_LOG_BOGON].valeur.integer + config[CF_ALR_BOGON].valeur.integer != FALSE &&
		
		// is an arp request
		flag_is_arp == TRUE &&

		// verif timeout
		timeact - eth_data->lastalert[6] >= config[CF_ANTIFLOOD_INTER].valeur.integer &&

		// if the bitfield is not active
		ISSET_MAC_ERROR(eth_data->alerts) == FALSE &&
		
		// if arp mac adress and eth mac adress are differents
		data_cmp(arp_mac_sender, eth_mac_sender) != 0
	) {
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %d] \"DETECTED", __FILE__, __LINE__);
		#endif
		
		eth_data->lastalert[6] = timeact;

		STR_ETH_MAC_SENDER
		STR_ARP_MAC_SENDER
		ARP_IP_SENDER

		if(config[CF_LOG_BOGON].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, reference=%s, type=mac_error",
			seq, str_eth_mac_sender, str_arp_ip_sender, str_arp_mac_sender);
		}
		if(config[CF_ALR_BOGON].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, str_arp_mac_sender, 6);
		}
	}

	// =====================================
	// excessive request by mac
	// =====================================
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %d] \"excessive request\" Check ...",			
	       __FILE__, __LINE__);
	#endif
	// increment counter for known mac sender
	if(flag_is_arp == TRUE && eth_data->timestamp == timeact){
		eth_data->request++;
	} else {
		eth_data->request = 1;
		eth_data->timestamp = timeact;
	}
	if(
		// check if loggued
		config[CF_LOG_ABUS].valeur.integer + config[CF_ALERT_ABUS].valeur.integer != FALSE &&
		
		// is an arp request
		flag_is_arp == TRUE &&
		
		// check the number of alerts
		eth_data->request == config[CF_ABUS].valeur.integer &&
	
		// if the bitfield is not active
		ISSET_RQ_ABUS(eth_data->alerts) == FALSE &&
		
		// chack anti flood
		timeact - eth_data->lastalert[5] >= config[CF_ANTIFLOOD_INTER].valeur.integer
	){
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %d] \"DETECTED", __FILE__, __LINE__);
		#endif
		
		// maj anti flood
		eth_data->lastalert[5] = timeact;

		STR_ETH_MAC_SENDER
		ARP_IP_SENDER

		if(config[CF_LOG_ABUS].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "sec=%d, mac=%s, ip=%s, type=rqabus", 
			       seq, str_eth_mac_sender, str_arp_ip_sender);
		}
		if(config[CF_ALERT_ABUS].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, "", 5);
		}	
	}
	
	// =====================================
	// know but not referenced in allow file
	// =====================================
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %d] \"know but not referenced in allow file\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// check if loggued
		config[CF_LOGALLOW].valeur.integer + config[CF_ALRALLOW].valeur.integer != FALSE &&
		
		// append but not in file
		eth_data->flag == APPEND &&

		// known from last check
		flag_unknown_address == FALSE &&

		// check flood
		timeact - eth_data->lastalert[1] >= config[CF_ANTIFLOOD_INTER].valeur.integer
	){
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %d] \"DETECTED", __FILE__, __LINE__);
		#endif
		
		// maj timeout
		eth_data->lastalert[1] = timeact;
	
		STR_ETH_MAC_SENDER
		ARP_IP_SENDER

		if(config[CF_LOGALLOW].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d mac=%s, ip=%s, type=unknow_address", 
			       seq, str_eth_mac_sender, str_arp_ip_sender);
		}
		if(config[CF_ALRALLOW].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, "", 1); 
		}
	}
	
	// =====================================
	// Present in deny file
	// =====================================
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %d] \"Present in deny file\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// check if loggued
		config[CF_LOGDENY].valeur.integer + config[CF_ALRDENY].valeur.integer != FALSE &&
		
		// mac is deny
		eth_data->flag == DENY &&

		// if the bitfield is not active
		ISSET_BLACK_LISTED(eth_data->alerts) == FALSE &&
		
		// chack for anti flood
		timeact - eth_data->lastalert[2] >= config[CF_ANTIFLOOD_INTER].valeur.integer
	){
		#ifdef DEBUG
		logmsg(LOG_DEBUG, "[%s %d] \"DETECTED", __FILE__, __LINE__);
		#endif
		
		// maj antiflood
		eth_data->lastalert[2] = timeact;

		STR_ETH_MAC_SENDER
		ARP_IP_SENDER

		if(config[CF_LOGDENY].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, type=black_listed",
			       seq, str_eth_mac_sender, str_arp_ip_sender);
		}
		if(config[CF_ALRDENY].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, "", 2); 
		}
	}
}

void cap_abus(void){
	abus = config[CF_ABUS].valeur.integer + 1;
}

