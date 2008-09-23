/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: arpalert.h 684 2008-03-28 18:01:29Z thierry $
 *
 */

#include <time.h>
#include <sys/time.h>

// time_t current_time;
struct timeval current_t;

// is forked
int is_forked;

