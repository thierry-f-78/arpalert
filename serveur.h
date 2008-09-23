/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: serveur.h 485 2007-03-12 18:09:43Z thierry $
 *
 */

#ifndef __SERVER_H
#define __SERVER_H

// run program as daemon
void daemonize(void);

// set security option (user separation, etc ...)
void separe(void);

#endif

