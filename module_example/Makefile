# Copyright (c) 2005-2010 Thierry FOURNIER
# $Id: Makefile 399 2006-10-29 08:09:10Z  $

CC = gcc
CFLAGS = -Wall -g

all: example.so

clean:
	rm -f *.o *.so

example.so: example.o
	${CC} ${CFLAGS} -shared -o example.so example.o
