/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: capture.h 238 2006-10-06 11:07:14Z thierry $
 *
 */

#ifndef __CAPTURE_H__
#define __CAPTURE_H__

// init capture system
void cap_init(void);

// launch capture system
void cap_sniff(void);

// reset global flood detection
void cap_abus(void);

#endif
