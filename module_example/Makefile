# Copyright (c) 2005-2010 Thierry FOURNIER
# $Id: Makefile 531 2007-08-03 18:49:58Z  $

CC = gcc
CFLAGS = -Wall -g

all: example.so

clean:
	-@rm -f *.o *.so

example.so: example.o
	${CC} ${CFLAGS} -shared -o example.so example.o
