/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: serveur.h 667 2007-11-17 14:26:13Z  $
 *
 */

#ifndef __SERVER_H
#define __SERVER_H

// run program as daemon
void daemonize(void);

// set security option (user separation, etc ...)
void separe(void);

#endif

