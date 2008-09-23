/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: serveur.h 471 2007-02-05 02:38:09Z thierry $
 *
 */

#ifndef __SERVER_H
#define __SERVER_H

// run program as daemon
void daemonize(void);

// set security option (user separation, etc ...)
void separe(void);

#endif

