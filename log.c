#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "log.h"
#include "loadconfig.h"
#ifdef USE_SYSLOG
#include <syslog.h>
#endif

void logmsg(int priority, const char *fmt, ...){
	va_list ap;
	char msg[4096];
	#ifndef USE_SYSLOG
	FILE *fp;
	#endif
	
	/* check if i do log this priority */
	if(priority > config[CF_LOGLEVEL].valeur.integer)return;

	va_start(ap, fmt);
	vsnprintf(msg, 4096, fmt, ap);
	va_end(ap);
	msg[4095] = 0;
	
	#ifdef USE_SYSLOG
	syslog(priority, msg); 
	#else
	if((fp = fopen(config[CF_LOGFILE].valeur.string, "a"))==NULL)exit(1);
	fputs(msg, fp);
	fclose(fp);
	#endif
}
