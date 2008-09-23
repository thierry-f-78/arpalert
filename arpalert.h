/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: arpalert.h 531 2007-08-03 18:49:58Z thierry $
 *
 */

#include <time.h>
#include <sys/time.h>

// time_t current_time;
struct timeval current_t;

// is forked
int is_forked;

