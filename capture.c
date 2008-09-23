/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: capture.c 313 2006-10-16 12:54:40Z thierry $
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
#include <errno.h>
#include <sys/select.h>
#include <sys/param.h>
#if (__Linux__ || __FreeBSD__ || __NetBSD__ || __OpenBSD__)
#    include <sys/sysctl.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#if (__NetBSD__ || __FreeBSD__ || __OpenBSD__)
#    include <net/if_dl.h>
#endif
#include <arpa/inet.h>

#include "arpalert.h"
#include "capture.h"
#include "sens.h"
#include "log.h"
#include "loadconfig.h"
#include "data.h"
#include "alerte.h"
#include "sens_timeouts.h"
#include "loadmodule.h"
#include "func_time.h"
#include "func_str.h"

#define SNAP_LEN 1514

extern int errno;

// constantes
//const char mac_empty[]  = "00:00:00:00:00:00";
struct ether_addr null_mac = { { 0, 0, 0, 0, 0, 0 } };
struct in_addr null_ip = { .s_addr = 0 };
struct in_addr broadcast = { .s_addr = 0xffffffff };
struct timeval next_abus_reset;

struct capt *first_capt;

// persistent var
int seq = 0;
int abus = 50;
int base = 21;
int count = 0;
struct timeval last_count;

void callback(u_char *, const struct pcap_pkthdr *, const u_char *);

pcap_t *cap_init_device(struct capt *cap_id){
	char err[PCAP_ERRBUF_SIZE];
	char filtre[1024];
	struct bpf_program bp;
	int promisc;
	pcap_t *idcap;

#if defined(__linux__)
	int sock_fd;
	struct ifreq ifr;
#endif

#if defined(__NetBSD__)||defined(__FreeBSD__)||defined(__OpenBSD__)
	int mib[6], len;
	char *buf;
	unsigned char *ptr;
	struct if_msghdr *ifm;
	struct sockaddr_dl *sdl;
#endif

	// find my arp adresses for this device
#if defined(__linux__)
	if((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ){
		logmsg(LOG_ERR, "[%s %i] Error in socket creation",
		                __FILE__, __LINE__);
		exit(1);
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy (ifr.ifr_name, cap_id->device, sizeof(ifr.ifr_name));
	if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) == -1 ) {
		logmsg(LOG_ERR, "[%s %i] Error in ioctl call",
		                __FILE__, __LINE__);
		exit(1);
	}
	DATA_CPY(&(cap_id->mac), &ifr.ifr_addr.sa_data);
#endif // defined(__linux__)

#if defined(__NetBSD__)||defined(__FreeBSD__)||defined(__OpenBSD__)
	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_LINK;
	mib[4] = NET_RT_IFLIST;
	if ((mib[5] = if_nametoindex(cap_id->device)) == 0) {
		logmsg(LOG_ERR, "[%s %i] if_nametoindex error",
		                __FILE__, __LINE__);
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
	DATA_CPY(&(cap_id->mac), ptr);
	free(buf);
#endif // (__NetBSD__)||defined(__FreeBSD__)||defined(__OpenBSD__)

	// generate filter
	if(config[CF_ONLY_ARP].valeur.integer == TRUE){
		sprintf(filtre, "arp or rarp");
	} else {
		*filtre = 0;
	}

	// promiscuous mode ?
	if(config[CF_PROMISC].valeur.integer==TRUE){
		promisc = 1;
	} else {
		promisc = 0;
	}
	
	// interface initialization 
	idcap = pcap_open_live(cap_id->device, SNAP_LEN, promisc, 0, err);
	if(idcap == NULL){
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

	return idcap;
}

void cap_init(void){
	struct capt *netif;
	char *device = NULL;
	char *base, *parse;
	int state, gbreak;
	char err[PCAP_ERRBUF_SIZE];

	first_capt = NULL;

	// if no device specified, auto select the first
	if(config[CF_IF].valeur.string == NULL ||
	   config[CF_IF].valeur.string[0] == 0){
		if((device = pcap_lookupdev(err))==NULL){
			logmsg(LOG_ERR, "[%s %i] pcap_lookupdev: %s",
			       __FILE__, __LINE__, err);
			exit(1);
		}
		logmsg(LOG_NOTICE, "Auto selected device: %s", device);

		netif = malloc(sizeof(struct capt));
		if(netif == NULL){
			logmsg(LOG_ERR,
			       "[%s %i] malloc: %s",
			       __FILE__, __LINE__, strerror(errno));
			exit(1);
		}
		netif->next = NULL;
		netif->device = strdup(device);
		netif->pcap = cap_init_device(netif);

		first_capt = netif;
	}

	// parsing conf
	else {
		base = strdup(config[CF_IF].valeur.string);
		parse = base;
		state = 0;
		gbreak = 0;
		while(TRUE){
			if(state == 0 && *parse != ','){
				device = parse;
				state = 1;
			}

			else if(state == 1 && ( *parse == ',' || *parse == 0)){
				if(*parse == 0) gbreak = 1;
				*parse = 0;
				state = 0;

				// generate node for interfaces chain and init interface
				netif = malloc(sizeof(struct capt));
				if(netif == NULL){
					logmsg(LOG_ERR,
					       "[%s %i] malloc: %s",
					       __FILE__, __LINE__, strerror(errno));
					exit(1);
				}
				netif->device = strdup(device);
				netif->pcap = cap_init_device(netif);

				logmsg(LOG_NOTICE, "Selected device: %s", device);

				// chain
				netif->next = first_capt;
				first_capt = netif;

				if(gbreak == 1) break;
			}

			else if(*parse == 0){
				logmsg(LOG_ERR, "Error when parsing device: \"%s\"\n", 
				       config[CF_IF].valeur.string);
				exit(1);
			}

			parse ++;
		}
		free(base);
	}

	gettimeofday(&next_abus_reset, NULL);
	last_count.tv_sec = next_abus_reset.tv_sec;
	last_count.tv_usec = next_abus_reset.tv_usec;
	next_abus_reset.tv_sec += 1;

}

// get device name and return pointeur to her struct capt
struct capt *cap_get_interface(char *device){
	struct capt *netif;

	netif = first_capt;
	while(netif != NULL){
		if(strcmp(device, netif->device)==0){
			return netif;
		}
		netif = netif->next;
	}
	return NULL;
}

// gen bitfield for select
int cap_gen_bitfield(fd_set *bf){
	struct capt *netif;
	int fd, max = 0;

	netif = first_capt;
	while(netif != NULL){
		fd = pcap_fileno(netif->pcap);
		FD_SET(fd, bf);
		if(fd > max) max = fd;
		netif = netif->next;
	}

	return(max);
}

// proceed return of select
void cap_sniff(fd_set *bf){
	struct capt *netif;

	netif = first_capt;
	while(netif != NULL){
		if(FD_ISSET(pcap_fileno(netif->pcap), bf)){
			if(pcap_dispatch(netif->pcap, 1, callback, (void*)netif) < 0){
				logmsg(LOG_ERR,
				       "[%s %i] pcap_dispatch error: %s",
				       __FILE__, __LINE__,
				       pcap_geterr(netif->pcap));
			}
		}
		netif = netif->next;
	}
}

// convert eth mac sender to string
#define STR_ETH_MAC_SENDER \
	if(flag_str_eth_mac_sender == FALSE){ \
		MAC_TO_STR(eth_mac_sender[0], str_eth_mac_sender); \
		flag_str_eth_mac_sender = TRUE; \
	}

// convert eth mac rcpt to string
#define STR_ETH_MAC_RCPT \
	if(flag_str_eth_mac_rcpt == FALSE){ \
		MAC_TO_STR(eth_mac_rcpt[0], str_eth_mac_rcpt); \
		flag_str_eth_mac_rcpt = TRUE; \
	}

// convert arp mac sender to sting
#define STR_ARP_MAC_SENDER \
	if(flag_str_arp_mac_sender == FALSE){ \
		MAC_TO_STR(arp_mac_sender[0], str_arp_mac_sender); \
		flag_str_arp_mac_sender = TRUE;	\
	}	

// convert arp mac sender to sting
#define STR_ARP_MAC_RCPT \
	if(flag_str_arp_mac_rcpt == FALSE){ \
		MAC_TO_STR(arp_mac_rcpt[0], str_arp_mac_rcpt); \
		flag_str_arp_mac_rcpt= TRUE;	\
	}	

// convert arp ip sender into string
#define STR_ARP_IP_SENDER \
	if(flag_str_arp_ip_sender == FALSE){ \
		strcpy(str_arp_ip_sender, inet_ntoa(arp_ip_sender)); \
		flag_str_arp_ip_sender = TRUE; \
	}

// convert arp ip rcpt into string
#define STR_ARP_IP_RCPT \
	if(flag_str_arp_ip_rcpt == FALSE){ \
		strcpy(str_arp_ip_rcpt, inet_ntoa(arp_ip_rcpt)); \
		flag_str_arp_ip_rcpt = TRUE; \
	}

// return TRUE if the alert interval is ok
int interval_ok(struct timeval *tv){
	struct timeval res;

	time_sous(&current_t, tv, &res);
	if(res.tv_sec >= config[CF_ANTIFLOOD_INTER].valeur.integer){
		return TRUE;
	}
	return FALSE;
}

void callback(u_char *user, const struct pcap_pkthdr *h,
                            const u_char *buff){
	char m_eth_mac_sender[18];
	char m_eth_mac_rcpt[18];
	char m_arp_mac_sender[18];
	char m_arp_mac_rcpt[18];
	char m_arp_ip_sender[16];
	char m_arp_ip_rcpt[16];

	int flag_is_arp = FALSE;
	struct ether_addr *eth_mac_sender = (struct ether_addr *)&null_mac;
	struct ether_addr *eth_mac_rcpt   = (struct ether_addr *)&null_mac;
	struct ether_addr *arp_mac_sender = (struct ether_addr *)&null_mac;
	struct ether_addr *arp_mac_rcpt   = (struct ether_addr *)&null_mac;
	struct in_addr arp_ip_sender = { .s_addr = 0x00000000 };
	struct in_addr arp_ip_rcpt   = { .s_addr = 0x00000000 };
	struct data_pack *eth_data = NULL;
	struct data_pack *ip_data  = NULL;
	char *str_eth_mac_sender = m_eth_mac_sender;
	char *str_eth_mac_rcpt   = m_eth_mac_rcpt;
	char *str_arp_mac_sender = m_arp_mac_sender;
	char *str_arp_mac_rcpt   = m_arp_mac_rcpt;
	char *str_arp_ip_sender  = m_arp_ip_sender;
	char *str_arp_ip_rcpt    = m_arp_ip_rcpt;
	int flag_str_eth_mac_sender = FALSE;
	int flag_str_eth_mac_rcpt   = FALSE;
	int flag_str_arp_mac_sender = FALSE;
	int flag_str_arp_mac_rcpt   = FALSE;
	int flag_str_arp_ip_sender  = FALSE; 
	int flag_str_arp_ip_rcpt    = FALSE;
	int flag_unknown_address    = TRUE;
	struct capt *cap_id= (struct capt *)user;
	struct timeval sous;

	// inter
	struct ether_header * eth_header;
	struct arphdr * arp_header;
	struct timeval res;

	// for dump;
	char ip_tmp[16];
	char mac_tmp[18];

	// if dump paquet is active
	#ifdef DEBUG_DUMP
	{
		char strdump[160];
		int i;
		char *c;
	
		i = 0;
		bzero(strdump, 160);
		c = strdump;
		while(i < 53){
			if(i % 6 == 0 && i != 0){
				*(c - 1) = 0;
				logmsg(LOG_DEBUG, "%s", strdump);
				bzero(strdump, 160);
				c = strdump;
			}
			sprintf(c, "%02x", buff[i]);
			c += 2;
			*c = ' ';
			c++;
			i++;
		}
		*(c - 1) = 0;
		logmsg(LOG_DEBUG, "%s", strdump);
	}
	#endif

	// if more than N arp request in one second,
	// dont execute capture functions
	time_sous(&current_t, &last_count, &res);
	if(count > config[CF_ANTIFLOOD_GLOBAL].valeur.integer &&
	   res.tv_sec < config[CF_ANTIFLOOD_INTER].valeur.integer) {
		return;
	}
	
	#ifdef DEBUG
	logmsg(LOG_DEBUG, "[%s %i] capture packet", __FILE__, __LINE__);
	#endif

	//increment sequence
	seq++;

	// set structurs
	eth_header = (struct ether_header *)buff;

	// get a ethernet mac source
	eth_mac_sender = (struct ether_addr *)&(eth_header->ether_shost);

	// get a ethernet mac dest
	eth_mac_rcpt = (struct ether_addr *)&(eth_header->ether_dhost);

	// get properties memorised of this mac
	eth_data = data_exist(eth_mac_sender, cap_id);
	if(eth_data != NULL) {
		flag_unknown_address = FALSE;
	}

	// is an arp request
	if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
		char *arp_data_base;

		// type la partie mac address
		arp_header = (struct arphdr *)(buff +
		             sizeof(struct ether_header));

		// is an arp who-has or is-at ?
		if(ntohs(arp_header->ar_op) == ARPOP_REQUEST ||
		   ntohs(arp_header->ar_op) == ARPOP_REPLY ){
		
			// set flag "is arp"
			flag_is_arp = TRUE;
			
			// count number of request in 1 second
			time_sous(&current_t, &last_count, &res);
			if(res.tv_sec < 1){
				count ++;
			} else {
				count = 1;
				last_count.tv_sec++;
			}
		}
		
		// compute the base (sender MAC address)
		arp_data_base = (char *)(buff + 
		                sizeof(struct ether_header) + 
		                sizeof(struct arphdr));

		// get arp mac sender
		// arp_mac_sender = (struct ether_addr *)&buff[base + 1];
		arp_mac_sender = (struct ether_addr *)arp_data_base;

		// base = sender IP address
		arp_data_base += arp_header->ar_hln;

		// get ip of arp sender
		arp_ip_sender.s_addr = *(U_INT32_T *)arp_data_base;
	
		// base = target IP address
		arp_data_base += ( arp_header->ar_pln + arp_header->ar_hln );
		
		// get ip of arp rcpt
		arp_ip_rcpt.s_addr = *(U_INT32_T *)arp_data_base;

		if(config[CF_DUMP_PAQUET].valeur.integer == TRUE){
			if(ntohs(arp_header->ar_op) == ARPOP_REQUEST) {
				STR_ETH_MAC_SENDER
				STR_ETH_MAC_RCPT
				STR_ARP_MAC_SENDER
				STR_ARP_MAC_RCPT
				STR_ARP_IP_SENDER
				STR_ARP_IP_RCPT

				logmsg(LOG_DEBUG, 
				       "[%s %d] %s > %s, "
				       "length %d: arp who-has %s tell %s",
						 __FILE__, __LINE__,
				       str_eth_mac_sender,
				       str_eth_mac_rcpt,
				       h->len,
				       str_arp_ip_rcpt,
						 str_arp_ip_sender);
			}

			else if(ntohs(arp_header->ar_op) == ARPOP_REPLY) {
				STR_ETH_MAC_SENDER
				STR_ETH_MAC_RCPT
				STR_ARP_MAC_SENDER
				STR_ARP_MAC_RCPT
				STR_ARP_IP_SENDER
				STR_ARP_IP_RCPT
	
				logmsg(LOG_DEBUG, 
				       "[%s %d] %s > %s, "
						 "length %d: arp reply %s is-at %s",
						 __FILE__, __LINE__,
				       str_eth_mac_sender,
				       str_eth_mac_rcpt,
						 h->len,
				       str_arp_ip_sender,
				       str_arp_mac_sender);
			}
		}
	}
	
	// =====================================
	// ARP general flood detection
	// =====================================
	#ifdef DEBUG_DETECT
	logmsg(LOG_DEBUG,
	       "[%s %d]  -> \"ARP general flood detection\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// is an arp request
		flag_is_arp == TRUE &&

		// global arp flood
		count > config[CF_ANTIFLOOD_GLOBAL].valeur.integer
	){
		#ifdef DEBUG_DETECT
		logmsg(LOG_DEBUG, "[%s %d]  -> DETECTED", __FILE__, __LINE__);
		#endif

		STR_ETH_MAC_SENDER
		STR_ARP_IP_SENDER
		STR_ARP_IP_RCPT
		
		if(config[CF_LOG_FLOOD].valeur.integer == TRUE){
			logmsg(LOG_NOTICE,
			       "seq=%d, mac=%s, ip=%s, type=flood, dev=%s",
			       seq, str_eth_mac_sender, str_arp_ip_sender,
			       cap_id->device);
		}
		if(config[CF_ALERT_FLOOD].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, "", 7);
		}
		if(config[CF_MOD_FLOOD].valeur.integer == TRUE){
			alerte_mod(eth_mac_sender, arp_ip_sender, 7,
			           &null_mac, null_ip, cap_id->device);
		}
		return;
	}
		
	// =====================================
	//  New mac adress detection
	// =====================================
	#ifdef DEBUG_DETECT
	logmsg(LOG_DEBUG,
	       "[%s %d]  -> \"New mac adress detection\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// mac adress inconue
		eth_data == NULL && 

		// ip unknown
		arp_ip_sender.s_addr == 0
	) {
		#ifdef DEBUG_DETECT
		logmsg(LOG_DEBUG, "[%s %d]  -> DETECTED", __FILE__, __LINE__);
		#endif
		
		// add data to database
		eth_data = data_add(eth_mac_sender, APPEND,
		                    arp_ip_sender, cap_id);

		// allow to dump data
		data_rqdump();

		STR_ETH_MAC_SENDER
		STR_ARP_IP_SENDER
		
		if(config[CF_LOG_NEWMAC].valeur.integer == TRUE){
			logmsg(LOG_NOTICE,
			       "seq=%d, mac=%s, ip=%s, type=new_mac, dev=%s",
			       seq, str_eth_mac_sender, str_arp_ip_sender,
			       cap_id->device);
		}
		if(config[CF_ALERT_NEWMAC].valeur.integer == TRUE){	
			alerte(str_eth_mac_sender, str_arp_ip_sender, "", 8);
		}
		if(config[CF_MOD_NEWMAC].valeur.integer == TRUE){
			alerte_mod(eth_mac_sender, arp_ip_sender, 8, &null_mac, null_ip, cap_id->device);
		}
	}

	// =====================================
	//  New mac adress and ip detection
	// =====================================
	#ifdef DEBUG_DETECT
	logmsg(LOG_DEBUG,
	       "[%s %d]  -> \"New mac adress and ip detection\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if (
		// ip known
		arp_ip_sender.s_addr != 0 &&
		
		(
			// mac adress inconue
			eth_data == NULL ||

			// ip inconue
			eth_data->ip.s_addr == 0
		)
	) {
		#ifdef DEBUG_DETECT
		logmsg(LOG_DEBUG, "[%s %d] DETECTED", __FILE__, __LINE__);
		#endif
		
		// add data to database
		if(eth_data == NULL) {
			eth_data = data_add(eth_mac_sender, APPEND,
			                    arp_ip_sender, cap_id);
		} else {
			eth_data->ip.s_addr = arp_ip_sender.s_addr;
			index_ip(eth_data);
		}
			
		// allow to dump data
		data_rqdump();

		STR_ETH_MAC_SENDER
		STR_ARP_IP_SENDER

		if(config[CF_LOG_NEW].valeur.integer == TRUE){
			logmsg(LOG_NOTICE,
			       "seq=%d, mac=%s, ip=%s, type=new, dev=%s",
			       seq, str_eth_mac_sender, str_arp_ip_sender,
			       cap_id->device);
		}
		if(config[CF_ALERT_NEW].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, "", 3);
		}
		if(config[CF_MOD_NEW].valeur.integer == TRUE){
			alerte_mod(eth_mac_sender, arp_ip_sender, 3,
			           &null_mac, null_ip, cap_id->device);
		}
	}
	
	// =====================================
	// test mac change
	// =====================================
	#ifdef DEBUG_DETECT
	logmsg(LOG_DEBUG,
	       "[%s %d]  -> \"test mac change\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// check if this alert is configured
		(
			config[CF_ALERT_MACCHG].valeur.integer == TRUE ||
			config[CF_LOG_MACCHG].valeur.integer == TRUE ||
			config[CF_MOD_MACCHG].valeur.integer == TRUE
		) &&

		// sender is known
		arp_ip_sender.s_addr != 0 &&

		// if the bitfield is not active
		ISSET_MAC_CHANGE(eth_data->alerts) == FALSE &&
		
		// sender exist
		(ip_data = data_ip_exist(arp_ip_sender, cap_id)) != NULL &&

		// have different mac address
		//data_cmp(&ip_data->mac.octet[0], eth_mac_sender) != 0
		//ip_data != eth_data
		DATA_CMP(&ip_data->mac.ETHER_ADDR_OCTET[0],
		         &eth_data->mac.ETHER_ADDR_OCTET[0]) != 0
	){
		#ifdef DEBUG_DETECT
		logmsg(LOG_DEBUG, "[%s %d]  -> DETECTED", __FILE__, __LINE__);
		#endif

		STR_ETH_MAC_SENDER
		STR_ARP_IP_SENDER
		MAC_TO_STR(ip_data->mac, mac_tmp);

		// maj ip in database
		unindex_ip(arp_ip_sender, cap_id);
		eth_data->ip.s_addr = arp_ip_sender.s_addr;
		index_ip(eth_data);

		// can dump database
		data_rqdump();
	
		if(config[CF_LOG_MACCHG].valeur.integer == TRUE){
			logmsg(LOG_NOTICE,
			       "seq=%d, mac=%s, ip=%s, reference=%s, type=mac_change, dev=%s",
			       seq, str_eth_mac_sender, str_arp_ip_sender,
			       mac_tmp, cap_id->device);
		}
		if(config[CF_ALERT_MACCHG].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, mac_tmp, 9);
		}
		if(config[CF_MOD_MACCHG].valeur.integer == TRUE){
			alerte_mod(eth_mac_sender, arp_ip_sender, 9, &ip_data->mac, null_ip, cap_id->device);
		}
	}

	// =====================================
	// test ip change
	// =====================================
	#ifdef DEBUG_DETECT
	logmsg(LOG_DEBUG,
	       "[%s %d]  -> \"test ip change\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// check if this alert is configured
		(
			config[CF_LOG_IPCHG].valeur.integer == TRUE ||
			config[CF_ALERT_IPCHG].valeur.integer == TRUE ||
			config[CF_MOD_IPCHG].valeur.integer == TRUE
		) &&
	
		// if ip known different than ip detected
		eth_data->ip.s_addr != arp_ip_sender.s_addr &&

		// if ip known differnent then a broadcast
		// ( protect aliases )
		eth_data->ip.s_addr != broadcast.s_addr &&
			
		// if ip known different than a nul adress
		// (mac already detected but whitout ip)
		eth_data->ip.s_addr != 0 &&

		// ip detected different than null adress
		arp_ip_sender.s_addr != 0 &&
			
		// if the bitfield is not active
		ISSET_IP_CHANGE(eth_data->alerts) == FALSE &&
		
		// check timeouts
		interval_ok(&(eth_data->lastalert[0])) == TRUE
	){
		#ifdef DEBUG_DETECT
		logmsg(LOG_DEBUG, "[%s %d]  -> DETECTED", __FILE__, __LINE__);
		#endif
		
		// maj timeout
		eth_data->lastalert[0].tv_sec = current_t.tv_sec;
		eth_data->lastalert[0].tv_usec = current_t.tv_usec;
					
		// convert ip to string
		strcpy(ip_tmp, inet_ntoa(eth_data->ip));
		STR_ETH_MAC_SENDER
		STR_ARP_IP_SENDER

		// maj database
		eth_data->ip.s_addr = arp_ip_sender.s_addr;
		index_ip(eth_data);

		// can dump database
		data_rqdump();
	
		if(config[CF_LOG_IPCHG].valeur.integer == TRUE){
			logmsg(LOG_NOTICE,
			       "seq=%d, mac=%s, ip=%s, reference=%s, type=ip_change, dev=%s",
			       seq, str_eth_mac_sender, str_arp_ip_sender,
			       ip_tmp, cap_id->device); 
		}	
		if(config[CF_ALERT_IPCHG].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, ip_tmp, 0); 
		}
		if(config[CF_MOD_IPCHG].valeur.integer == TRUE){
			alerte_mod(eth_mac_sender, arp_ip_sender, 0, &null_mac, eth_data->ip, cap_id->device);
		}
	}

	// =====================================
	// non authorized request
	// =====================================
	#ifdef DEBUG_DETECT
	logmsg(LOG_DEBUG,
	       "[%s %d]  -> \"non authorized request\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// check if this alert is configured
		(
			config[CF_LOG_UNAUTH_RQ].valeur.integer == TRUE ||
			config[CF_ALERT_UNAUTH_RQ].valeur.integer == TRUE ||
			config[CF_MOD_UNAUTH_RQ].valeur.integer == TRUE
		) &&
		
		// is an arp request
		flag_is_arp == TRUE &&

		// the authfile do not complited
		config[CF_AUTHFILE].valeur.string != NULL &&
		
		// if the bitfield is not active
		ISSET_UNAUTH_RQ(eth_data->alerts) == FALSE &&
		
		// if ignore me is active
		(
			config[CF_IGNORE_ME].valeur.integer == FALSE ||
			(
				DATA_CMP(&(cap_id->mac), eth_mac_rcpt) != 0 &&
				DATA_CMP(&(cap_id->mac), eth_mac_sender) != 0
			)
		) &&
		
		(
			// permit to ignore acl for not referenced machines
			config[CF_IGNORE_UNKNOWN].valeur.integer == FALSE ||
			eth_data->flag == ALLOW
		) &&
			
		(
			// permit to ignore arp self test
			config[CF_IGNORESELFTEST].valeur.integer == FALSE ||
			eth_data->ip.s_addr != arp_ip_rcpt.s_addr
		) &&

		(
			(
				// normal flood control 
				config[CF_UNAUTH_TO_METHOD].valeur.integer == 1 &&
				interval_ok(&(eth_data->lastalert[4])) == TRUE
			) ||

			(
				// flood control by tuple (mac / ip)
				config[CF_UNAUTH_TO_METHOD].valeur.integer == 2 &&
				sens_timeout_exist(eth_mac_sender, arp_ip_rcpt, cap_id) == FALSE
			)
		) &&
			
		// check if request is authorized
		sens_exist(eth_mac_sender, arp_ip_rcpt, cap_id) == FALSE

	){
		#ifdef DEBUG_DETECT
		logmsg(LOG_DEBUG, "[%s %d]  -> DETECTED", __FILE__, __LINE__);
		#endif
		
		// add info for advanced timeouts 
		/*
		if(config[CF_UNAUTH_TO_METHOD].valeur.integer == 2 &&
		   config[CF_ANTIFLOOD_INTER].valeur.integer != 0){
		*/
		if(config[CF_UNAUTH_TO_METHOD].valeur.integer == 2){
			sens_timeout_add(eth_mac_sender, arp_ip_rcpt, cap_id);
		}

		// add info for simple timeout
		eth_data->lastalert[4].tv_sec = current_t.tv_sec;
		eth_data->lastalert[4].tv_usec = current_t.tv_usec;

		STR_ETH_MAC_SENDER
		STR_ARP_IP_SENDER
		STR_ARP_IP_RCPT

		// ALERT
		if(config[CF_LOG_UNAUTH_RQ].valeur.integer == TRUE){
			logmsg(LOG_NOTICE, "seq=%d, mac=%s, ip=%s, rq=%s, "
			                   "type=unauthrq, dev=%s", 
			       seq, str_eth_mac_sender, str_arp_ip_sender,
			       str_arp_ip_rcpt, cap_id->device);
		}
		if(config[CF_ALERT_UNAUTH_RQ].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, str_arp_ip_rcpt, 4);
		}
		if(config[CF_MOD_UNAUTH_RQ].valeur.integer == TRUE){
			alerte_mod(eth_mac_sender, arp_ip_sender, 4,
			           &null_mac, arp_ip_rcpt, cap_id->device);
		}
	}

	// =====================================
	// error with ethernet mac and arp mac
	// =====================================
	#ifdef DEBUG_DETECT
	logmsg(LOG_DEBUG,
	       "[%s %d]  -> \"error with ethernet mac and arp mac\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// check if loggued
		(
			config[CF_LOG_BOGON].valeur.integer == TRUE || 
			config[CF_ALERT_BOGON].valeur.integer == TRUE ||
			config[CF_MOD_BOGON].valeur.integer == TRUE
		) &&
		
		// is an arp request
		flag_is_arp == TRUE &&

		// verif timeout
		interval_ok(&(eth_data->lastalert[6])) == TRUE &&

		// if the bitfield is not active
		ISSET_MAC_ERROR(eth_data->alerts) == FALSE &&
		
		// if arp mac adress and eth mac adress are differents
		DATA_CMP(arp_mac_sender, eth_mac_sender) != 0
	) {
		#ifdef DEBUG_DETECT
		logmsg(LOG_DEBUG, "[%s %d]  -> DETECTED", __FILE__, __LINE__);
		#endif
		
		eth_data->lastalert[6].tv_sec = current_t.tv_sec;
		eth_data->lastalert[6].tv_usec = current_t.tv_usec;

		STR_ETH_MAC_SENDER
		STR_ARP_MAC_SENDER
		STR_ARP_IP_SENDER

		if(config[CF_LOG_BOGON].valeur.integer == TRUE){
			logmsg(LOG_NOTICE,
			       "seq=%d, mac=%s, ip=%s, reference=%s, "
					 "type=mac_error, dev=%s",
			       seq, str_eth_mac_sender, str_arp_ip_sender,
			       str_arp_mac_sender, cap_id->device);
		}
		if(config[CF_ALERT_BOGON].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender,
			       str_arp_mac_sender, 6);
		}
		if(config[CF_MOD_BOGON].valeur.integer == TRUE){
			alerte_mod(eth_mac_sender, arp_ip_sender, 6,
			           arp_mac_sender, null_ip, cap_id->device);
		}
	}

	// =====================================
	// excessive request by mac
	// =====================================
	#ifdef DEBUG_DETECT
	logmsg(LOG_DEBUG,
	       "[%s %d]  -> \"excessive request\" Check ...",			
	       __FILE__, __LINE__);
	#endif
	// increment counter for known mac sender
	time_sous(&current_t, &(eth_data->timestamp), &sous);
	if(flag_is_arp == TRUE &&
	   sous.tv_sec == 0){
		eth_data->request++;
	} else {
		eth_data->request = 1;
		index_timeout(eth_data);
	}
	if(
		// check if loggued
		(
			config[CF_LOG_ABUS].valeur.integer == TRUE ||
			config[CF_ALERT_ABUS].valeur.integer == TRUE || 
			config[CF_MOD_ABUS].valeur.integer == TRUE 
		) &&
		
		// is an arp request
		flag_is_arp == TRUE &&
		
		// check the number of alerts
		eth_data->request == config[CF_ABUS].valeur.integer &&
	
		// if the bitfield is not active
		ISSET_RQ_ABUS(eth_data->alerts) == FALSE &&
		
		// chack anti flood
		interval_ok(&(eth_data->lastalert[5])) == TRUE
	){
		#ifdef DEBUG_DETECT
		logmsg(LOG_DEBUG, "[%s %d]  -> DETECTED", __FILE__, __LINE__);
		#endif
		
		// maj anti flood
		eth_data->lastalert[5].tv_sec = current_t.tv_sec;
		eth_data->lastalert[5].tv_usec = current_t.tv_usec;

		STR_ETH_MAC_SENDER
		STR_ARP_IP_SENDER

		if(config[CF_LOG_ABUS].valeur.integer == TRUE){
			logmsg(LOG_NOTICE,
			       "sec=%d, mac=%s, ip=%s, type=rqabus, dev=%s", 
			       seq, str_eth_mac_sender, str_arp_ip_sender,
			       cap_id->device);
		}
		if(config[CF_ALERT_ABUS].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, "", 5);
		}	
		if(config[CF_MOD_ABUS].valeur.integer == TRUE){
			alerte_mod(eth_mac_sender, arp_ip_sender, 5,
			           &null_mac, null_ip, cap_id->device);
		}
	}
	
	// =====================================
	// know but not referenced in allow file
	// =====================================
	#ifdef DEBUG_DETECT
	logmsg(LOG_DEBUG,
	       "[%s %d]  -> \"know but not referenced in allow file\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// check if loggued
		(
			config[CF_LOG_ALLOW].valeur.integer == TRUE ||
			config[CF_ALERT_ALLOW].valeur.integer == TRUE ||
			config[CF_MOD_ALLOW].valeur.integer == TRUE
		) &&
		
		// append but not in file
		eth_data->flag == APPEND &&

		// known from last check
		flag_unknown_address == FALSE &&

		// check flood
		interval_ok(&(eth_data->lastalert[1])) == TRUE
	){
		#ifdef DEBUG_DETECT
		logmsg(LOG_DEBUG, "[%s %d]  -> DETECTED", __FILE__, __LINE__);
		#endif
		
		// maj timeout
		eth_data->lastalert[1].tv_sec = current_t.tv_sec;
		eth_data->lastalert[1].tv_usec = current_t.tv_usec;
	
		STR_ETH_MAC_SENDER
		STR_ARP_IP_SENDER

		if(config[CF_LOG_ALLOW].valeur.integer == TRUE){
			logmsg(LOG_NOTICE,
			       "seq=%d, mac=%s, ip=%s, type=unknow_address, dev=%s", 
			       seq, str_eth_mac_sender, str_arp_ip_sender,
			       cap_id->device);
		}
		if(config[CF_ALERT_ALLOW].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, "", 1); 
		}
		if(config[CF_MOD_ALLOW].valeur.integer == TRUE){
			alerte_mod(eth_mac_sender, arp_ip_sender, 1,
			           &null_mac, null_ip, cap_id->device);
		}
	}
	
	// =====================================
	// Present in deny file
	// =====================================
	#ifdef DEBUG_DETECT
	logmsg(LOG_DEBUG,
	       "[%s %d]  -> \"Present in deny file\" Check ...",
	       __FILE__, __LINE__);
	#endif
	if(
		// check if loggued
		(
			config[CF_LOG_DENY].valeur.integer == TRUE ||
			config[CF_ALERT_DENY].valeur.integer == TRUE ||
			config[CF_MOD_DENY].valeur.integer == TRUE
		) &&
		
		// mac is deny
		eth_data->flag == DENY &&

		// if the bitfield is not active
		ISSET_BLACK_LISTED(eth_data->alerts) == FALSE &&
		
		// chack for anti flood
		interval_ok(&(eth_data->lastalert[2])) == TRUE
	){
		#ifdef DEBUG_DETECT
		logmsg(LOG_DEBUG, "[%s %d]  -> DETECTED", __FILE__, __LINE__);
		#endif
		
		// maj antiflood
		eth_data->lastalert[2].tv_sec = current_t.tv_sec;
		eth_data->lastalert[2].tv_usec = current_t.tv_usec;

		STR_ETH_MAC_SENDER
		STR_ARP_IP_SENDER

		if(config[CF_LOG_DENY].valeur.integer == TRUE){
			logmsg(LOG_NOTICE,
			       "seq=%d, mac=%s, ip=%s, type=black_listed, dev=%s",
			       seq, str_eth_mac_sender, str_arp_ip_sender,
			       cap_id->device);
		}
		if(config[CF_ALERT_DENY].valeur.integer == TRUE){
			alerte(str_eth_mac_sender, str_arp_ip_sender, "", 2); 
		}
		if(config[CF_MOD_DENY].valeur.integer == TRUE){
			alerte_mod(eth_mac_sender, arp_ip_sender, 2,
			           &null_mac, null_ip, cap_id->device);
		}
	}
}

void cap_abus(void){
	#ifdef DEBUG
	logmsg(LOG_DEBUG,
	       "[%s %d] running abus reset",
	       __FILE__, __LINE__);
	#endif

	abus = config[CF_ABUS].valeur.integer + 1;
	next_abus_reset.tv_sec ++;
}

// return the next timeout
void *cap_next(struct timeval *tv){
	(*tv).tv_sec = next_abus_reset.tv_sec;
	(*tv).tv_usec = next_abus_reset.tv_usec;
	return cap_abus;
}

