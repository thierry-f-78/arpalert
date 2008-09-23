/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: sens.h 124 2006-05-10 21:46:12Z thierry $
 *
 */

#ifndef __SENS_H__
#define __SENS_H__

#include "data.h"

// init data
void sens_init(void);

// free data memory
void sens_free(void);

// reload data
void sens_reload(void);

// add sens to hash
void sens_add(data_mac *, data_ip, u_int32_t);

// test if sens exists
int  sens_exist(data_mac *, data_ip);

#endif
