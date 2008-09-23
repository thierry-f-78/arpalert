# Copyright (c) 2005-2010 Thierry FOURNIER
# $Id: Makefile 471 2007-02-05 02:38:09Z  $

CC = gcc
CFLAGS = -Wall -g

all: example.so

clean:
	rm -f *.o *.so

example.so: example.o
	${CC} ${CFLAGS} -shared -o example.so example.o
