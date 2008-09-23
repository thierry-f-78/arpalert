# Copyright (c) 2005-2010 Thierry FOURNIER
# $Id: Makefile 684 2008-03-28 18:01:29Z  $

CC = gcc
CFLAGS = -Wall -g

all: example.so

clean:
	-@rm -f *.o *.so

example.so: example.o
	${CC} ${CFLAGS} -fPIC -shared -o example.so example.o
