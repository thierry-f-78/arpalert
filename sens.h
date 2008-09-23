/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: sens.h 223 2006-10-05 19:44:46Z thierry $
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
void sens_add(struct ether_addr *mac, struct in_addr ip, struct in_addr mask);

// test if sens exists
int  sens_exist(struct ether_addr *mac, struct in_addr ip);

#endif
