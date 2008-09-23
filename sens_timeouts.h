/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: sens_timeouts.h 124 2006-05-10 21:46:12Z thierry $
 *
 */

#ifndef __SENS_TIMEOUTS_H__
#define __SENS_TIMEOUTS_H__

#include "data.h"

// initialize data structures
void sens_timeout_init(void);

// add new detection timour tracking
void sens_timeout_add(data_mac *, data_ip);

// return TRUE if timeout is not expired
int  sens_timeout_exist(data_mac *, data_ip);

// cleanup timeout expireds
void sens_timeout_clean(void);

#endif

