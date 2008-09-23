/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: arpalert.h 485 2007-03-12 18:09:43Z thierry $
 *
 */

#include <time.h>
#include <sys/time.h>

// time_t current_time;
struct timeval current_t;

// is forked
int is_forked;

