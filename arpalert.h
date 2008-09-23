/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: arpalert.h 471 2007-02-05 02:38:09Z thierry $
 *
 */

#include <time.h>
#include <sys/time.h>

// time_t current_time;
struct timeval current_t;

// is forked
int is_forked;

