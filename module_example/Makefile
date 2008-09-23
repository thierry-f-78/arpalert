# Copyright (c) 2005-2010 Thierry FOURNIER
# $Id: Makefile 667 2007-11-17 14:26:13Z  $

CC = gcc
CFLAGS = -Wall -g

all: example.so

clean:
	-@rm -f *.o *.so

example.so: example.o
	${CC} ${CFLAGS} -fPIC -shared -o example.so example.o
