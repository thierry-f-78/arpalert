#ifndef __FUNC_TIME_H__
#define __FUNC_TIME_H__

#define BIGEST 1
#define EQUAL 0
#define SMALLEST -1

/* compare t1 and t2
 * si t1 > t2 =>  1
 * si t1 = t2 =>  0
 * si t1 < t2 => -1
 */
int time_comp(struct timeval *t1, struct timeval *t2);

// minus function for struct timeval
void time_sous(struct timeval *t1, struct timeval *t2, struct timeval *res);

#endif
