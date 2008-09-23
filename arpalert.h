/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: arpalert.h 508 2007-06-07 09:12:02Z thierry $
 *
 */

#include <time.h>
#include <sys/time.h>

// time_t current_time;
struct timeval current_t;

// is forked
int is_forked;

