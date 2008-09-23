/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id$
 *
 */

char *arpalert_alert_name[] = {
	"ip_change",
	"unknow_address",
	"black_listed",
	"new",
	"unauthrq",
	"rqabus",
	"mac_error",
	"flood",
	"new_mac",
	"mac_change"
};

/* @inputs
 *
 *   int type: type of alert
 *   int nargs: number of arguments
 *   void **data: argument list
 *
 * -----------------------------------------
 * alert             args    desc list
 * ------------------------------------------
 * 0 ip_change       4       interface, mac_sender, ip_sender, old_ip
 * 1 unknow_address  3       interface, mac_sender, ip_sender
 * 2 black_listed    3       interface, mac_sender, ip_sender
 * 3 new             3       interface, mac_sender, ip_sender
 * 4 unauthrq        4       interface, mac_sender, ip_sender, ip_requested
 * 5 rqabus          3       interface, mac_sender, ip_sender
 * 6 mac_error       4       interface, mac_sender, ip_sender, mac_in_arp_request
 * 7 flood           3       interface, mac_sender, ip_sender
 * 8 new_mac         3       interface, mac_sender, ip_sender,
 * 9 mac_change      4       interface, mac_sender, ip_sender, old_mac
 *
 * types:
 * char *interface
 * struct ether_addr *mac_sender
 * struct in_addr ip_sender
 * struct in_addr old_ip
 * struct in_addr ip_requested
 * struct ether_addr *mac_in_arp_request
 * struct ether_addr *old_mac
 *
 */
void mod_alert(int type, int nargs, void **data);

