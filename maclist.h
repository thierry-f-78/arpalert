/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: maclist.h 124 2006-05-10 21:46:12Z thierry $
 *
 */

#ifndef __MACLIST_H__
#define __MACLIST_H__

// load maclists file and update data system
void maclist_load(void);

// reload maclist file
void maclist_reload(void);

#endif
