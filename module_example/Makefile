# Copyright (c) 2005-2010 Thierry FOURNIER
# $Id: Makefile 508 2007-06-07 09:12:02Z  $

CC = gcc
CFLAGS = -Wall -g

all: example.so

clean:
	rm -f *.o *.so

example.so: example.o
	${CC} ${CFLAGS} -shared -o example.so example.o
