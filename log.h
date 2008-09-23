/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: log.h 60 2006-03-02 19:51:25Z thierry $
 *
 */

#ifndef __LOG_H__
#define __LOG_H__

// log priority.
#define LOG_EMERG       0
#define LOG_ALERT       1
#define LOG_CRIT        2
#define LOG_ERR         3
#define LOG_WARNING     4
#define LOG_NOTICE      5
#define LOG_INFO        6
#define LOG_DEBUG       7

// log initilization:
// open log file before chrooting
// send init and open syslog before chrooting
void initlog(void);

// send log message
void logmsg(int, const char *, ...);

#endif
