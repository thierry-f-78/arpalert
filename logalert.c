#include "config.h"

#include "log.h"
#include "loadconfig.h"

const char *alert_type[] = {
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

void alerte_log(int num_seq,
                char *mac_sender,
                char *ip_sender,
                int type,
                char *ref,
                char *interface,
                char *vendor){
	
	// log with mac vendor
	if(config[CF_LOG_VENDOR].valeur.integer == TRUE){
		switch(type){
			case 0:
			case 4:
			case 6:
			case 9:
				logmsg(LOG_NOTICE,
				       "seq=%d, mac=%s, ip=%s, reference=%s, "
				       "type=%s, dev=%s, vendor=\"%s\"",
				        num_seq, mac_sender, ip_sender, ref,
				        alert_type[type], interface, vendor);
				break;

			default:
				logmsg(LOG_NOTICE,
				       "seq=%d, mac=%s, ip=%s, type=%s, "
				       "dev=%s, vendor=\"%s\"",
				        num_seq, mac_sender, ip_sender,
				        alert_type[type], interface, vendor);
				break;
		}
	}

	// log whitout mac vendor
	else {
		switch(type){
			case 0:
			case 4:
			case 6:
			case 9:
				logmsg(LOG_NOTICE,
				       "seq=%d, mac=%s, ip=%s, reference=%s, "
				       "type=%s, dev=%s",
				        num_seq, mac_sender, ip_sender,
				        ref, alert_type[type], interface);
				break;

			default:
				logmsg(LOG_NOTICE,
				       "seq=%d, mac=%s, ip=%s, type=%s, "
				       "dev=%s",
				        num_seq, mac_sender, ip_sender,
				        alert_type[type], interface);
				break;
		}
	}
}

