/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: serveur.h 223 2006-10-05 19:44:46Z thierry $
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

