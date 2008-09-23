# Copyright (c) 2005-2010 Thierry FOURNIER
# $Id: Makefile 578 2007-08-27 13:57:26Z  $

CC = gcc
CFLAGS = -Wall -g

all: example.so

clean:
	-@rm -f *.o *.so

example.so: example.o
	${CC} ${CFLAGS} -fPIC -shared -o example.so example.o
