/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: serveur.h 450 2006-11-24 10:33:55Z thierry $
 *
 */

#ifndef __SERVER_H
#define __SERVER_H

// run program as daemon
void daemonize(void);

// set security option (user separation, etc ...)
void separe(void);

#endif

