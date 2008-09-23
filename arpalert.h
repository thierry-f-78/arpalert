/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: arpalert.h 578 2007-08-27 13:57:26Z thierry $
 *
 */

#include <time.h>
#include <sys/time.h>

// time_t current_time;
struct timeval current_t;

// is forked
int is_forked;

