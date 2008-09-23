/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: serveur.h 508 2007-06-07 09:12:02Z thierry $
 *
 */

#ifndef __SERVER_H
#define __SERVER_H

// run program as daemon
void daemonize(void);

// set security option (user separation, etc ...)
void separe(void);

#endif

