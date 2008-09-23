#ifndef __SERVER_H
#define __SERVER_H 1
void daemonize(void);
void (*setsignal (int, void (*)(int)))(int);
#endif

