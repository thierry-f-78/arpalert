/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: sens_timeouts.h 156 2006-09-28 17:10:55Z  $
 *
 */

#ifndef __SENS_TIMEOUTS_H__
#define __SENS_TIMEOUTS_H__

#include "data.h"

// initialize data structures
void sens_timeout_init(void);

// add new detection timour tracking
void sens_timeout_add(struct ether_addr *, struct in_addr);

// return TRUE if timeout is not expired
int  sens_timeout_exist(struct ether_addr *, struct in_addr);

// cleanup timeout expireds
void sens_timeout_clean(void);

#endif

