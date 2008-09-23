/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: arpalert.h 399 2006-10-29 08:09:10Z thierry $
 *
 */

#include <time.h>
#include <sys/time.h>

// time_t current_time;
struct timeval current_t;

// is forked
int is_forked;

