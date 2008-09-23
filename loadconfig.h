/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: loadconfig.h 139 2006-09-01 21:53:38Z thierry $
 *
 */

#ifndef __LOADCONFIG_H__
#define __LOADCONFIG_H__

/*
 * types:
 *  0: char
 *  1: int
 *  2: boolean
 *  3: octal
 *
 * attrib:
 *  parameter value in config file
 *
 * value:
 *  valeur du parametre de type indefini
 */

#define TRUE                1
#define FALSE               0

#define CF_MACLIST          0
#define CF_LOGFILE          1
#define CF_ACTION           2
#define CF_LOCKFILE         3
#define CF_DAEMON           4
#define CF_RELOAD           5
#define CF_LOGLEVEL         6
#define CF_TIMEOUT          7
#define CF_MAXTH            8
#define CF_BLACKLST         9
#define CF_LEASES           10
#define CF_IF               11
#define CF_ABUS             12
#define CF_MAXENTRY         13
#define CF_DMPWL            14
#define CF_DMPBL            15
#define CF_DMPAPP           16
#define CF_TOOOLD           17
#define CF_LOGALLOW         18
#define CF_ALRALLOW         19
#define CF_LOGDENY          20
#define CF_ALRDENY          21
#define CF_LOGNEW           22
#define CF_ALRNEW           23
#define CF_ALRIP            24
#define CF_LOGIP            25
#define CF_AUTHFILE         26
#define CF_LOG_UNAUTH_RQ    27
#define CF_ALERT_UNAUTH_RQ  28
#define CF_LOG_ABUS         29
#define CF_ALERT_ABUS       30
#define CF_LOG_BOGON        31
#define CF_ALR_BOGON        32
#define CF_IGNORE_UNKNOWN   33
#define CF_DUMP_PAQUET      34
#define CF_PROMISC          35
#define CF_ANTIFLOOD_INTER  36
#define CF_ANTIFLOOD_GLOBAL 37
#define CF_LOG_FLOOD        38
#define CF_ALERT_ON_FLOOD   39
#define CF_IGNORE_ME        40
#define CF_UMASK            41
#define CF_USER             42
#define CF_CHROOT           43
#define CF_USESYSLOG        44
#define CF_IGNORESELFTEST   45
#define CF_UNAUTH_TO_METHOD 46
#define CF_LOGNEWMAC        47
#define CF_ALRNEWMAC        48
#define CF_LOG_MACCHG       49
#define CF_ALERT_MACCHG     50

#define NUM_PARAMS          51

#define STRVAL_LEN 512
#define ATTRIB_LEN 512
#define CONFIGFILE_LEN 512

// if true, the data is updated
int flagdump;

typedef union {
	char	string[STRVAL_LEN];
	int	integer;
} config_val;

typedef struct {
	int		type;
	char		attrib[ATTRIB_LEN];
	config_val	valeur;
} config_cell;

config_cell config[NUM_PARAMS];
char config_file[CONFIGFILE_LEN];

// load config file values
void config_load(int, char **);

#endif
