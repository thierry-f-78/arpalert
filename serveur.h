/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: serveur.h 139 2006-09-01 21:53:38Z thierry $
 *
 */

#ifndef __SERVER_H
#define __SERVER_H

// run program as daemon
void daemonize(void);

// set security option (user separation, etc ...)
void separe(void);

// assign function to signal interuption
void (*setsignal (int, void (*)(int)))(int);

#endif

