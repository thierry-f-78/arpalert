# Copyright (c) 2005-2010 Thierry FOURNIER
# $Id: Makefile 223 2006-10-05 19:44:46Z  $

CC = gcc
CFLAGS = -Wall -g

all: example.so

clean:
	rm -f *.o *.so

example.so: example.o
	${CC} ${CFLAGS} -shared -o example.so example.o
