/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: arpalert.h 344 2006-10-19 12:06:40Z  $
 *
 */

#include <time.h>
#include <sys/time.h>

// time_t current_time;
struct timeval current_t;

// is forked
int is_forked;

