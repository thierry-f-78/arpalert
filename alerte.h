/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: alerte.h 412 2006-11-03 18:33:17Z  $
 *
 */

#ifndef __ALERTE_H__
#define __ALERTE_H__

// send new alert
void alerte_script(char *mac, char *ip, int no, char *ref,
                   char *interface, char *vendor);

// init memory structurs
void alerte_init(void);

// return the next timeout and the functionn to call
void *alerte_next(struct timeval *tv);

// check validity of all current alert scripts
void alerte_check(void);

void alerte_kill_pid(void);

#endif
