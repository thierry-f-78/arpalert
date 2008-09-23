/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: arpalert.h 450 2006-11-24 10:33:55Z thierry $
 *
 */

#include <time.h>
#include <sys/time.h>

// time_t current_time;
struct timeval current_t;

// is forked
int is_forked;

