#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef USE_SYSLOG
#include <syslog.h>
#endif
#include "log.h"
#include "loadconfig.h"

FILE *lf;

void openlogfile(void);

void initlog(void){
	#ifdef USE_SYSLOG
	if(config[CF_USESYSLOG].valeur.integer == TRUE){
		openlog("arpalert", LOG_CONS, LOG_DAEMON);
	}
	#endif
	if(config[CF_LOGFILE].valeur.string[0] != 0)
		openlogfile();
}

void openlogfile(void){
	if((lf = fopen(config[CF_LOGFILE].valeur.string, "a"))==NULL){
		fprintf(stderr, "[%s %d] Cant't open file [%s]\n",
			__FILE__, __LINE__, config[CF_LOGFILE].valeur.string);
		exit(1);
	}
}

void logmsg(int priority, const char *fmt, ...){
	va_list ap;
	char msg[4096];
	char s_time[128];

	/* check if I do log this priority */
	if(priority > config[CF_LOGLEVEL].valeur.integer)return;

	#ifdef USE_SYSLOG
	if(config[CF_USESYSLOG].valeur.integer == TRUE){
		va_start(ap, fmt);
		vsyslog(priority, fmt, ap); 
		vsnprintf(msg, 4096, fmt, ap);
	}
	#endif

	if(config[CF_LOGFILE].valeur.string[0] != 0 || config[CF_DAEMON].valeur.integer == FALSE){
		//Oct  7 12:07:27 localhost arpalert: 
		snprintf(s_time, 128, "%d: ", (int)time(NULL));
		va_start(ap, fmt);
		vsnprintf(msg, 4096, fmt, ap);
		va_end(ap);
	}

	if(config[CF_LOGFILE].valeur.string[0] != 0){
		fprintf(lf, s_time);
		fprintf(lf, msg);
		fprintf(lf, "\n");
		fflush(lf);
	}

	if(config[CF_DAEMON].valeur.integer == FALSE){
		printf("%s", s_time);
		printf("%s", msg);
		printf("\n");
	}
}

