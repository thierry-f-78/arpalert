/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: serveur.h 399 2006-10-29 08:09:10Z thierry $
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

