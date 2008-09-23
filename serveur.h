/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: serveur.h 60 2006-03-02 19:51:25Z thierry $
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

