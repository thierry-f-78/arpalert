/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: logalert.h 667 2007-11-17 14:26:13Z  $
 *
 */

#ifndef __LOGALERT_H__
#define __LOGALERT_H__

void alerte_log(int num_seq,
                char *mac_sender,
                char *ip_sender,
                int type,
                char *ref,
                char *interface,
                char *vendor);

#endif
