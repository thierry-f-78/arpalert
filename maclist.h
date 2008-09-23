/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: maclist.h 471 2007-02-05 02:38:09Z thierry $
 *
 */

#ifndef __MACLIST_H__
#define __MACLIST_H__

// load maclists file and update data system
void maclist_load(void);

// reload maclist file
void maclist_reload(void);

#endif
