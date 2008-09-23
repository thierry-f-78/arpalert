/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: serveur.h 531 2007-08-03 18:49:58Z thierry $
 *
 */

#ifndef __SERVER_H
#define __SERVER_H

// run program as daemon
void daemonize(void);

// set security option (user separation, etc ...)
void separe(void);

#endif

