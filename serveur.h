/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: serveur.h 578 2007-08-27 13:57:26Z thierry $
 *
 */

#ifndef __SERVER_H
#define __SERVER_H

// run program as daemon
void daemonize(void);

// set security option (user separation, etc ...)
void separe(void);

#endif

