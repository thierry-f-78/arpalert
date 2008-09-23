# Copyright (c) 2005-2010 Thierry FOURNIER
# $Id: Makefile 450 2006-11-24 10:33:55Z  $

CC = gcc
CFLAGS = -Wall -g

all: example.so

clean:
	rm -f *.o *.so

example.so: example.o
	${CC} ${CFLAGS} -shared -o example.so example.o
