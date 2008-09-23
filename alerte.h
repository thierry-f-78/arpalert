/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: alerte.h 124 2006-05-10 21:46:12Z thierry $
 *
 */

#ifndef __ALERTE_H__
#define __ALERTE_H__

// send new alert
void alerte(char *, char *, char *, int);

// init memory structurs
void alerte_init(void);

// check validity of all current alert scripts
void alerte_check(void);

//void alerte_kill_pid(int signal);

#endif
