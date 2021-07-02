CC=gcc
INCLUDE=-I./
CFLAGS=-ggdb

sha1.o: sha1.c
	$(CC) -c $(CFLAGS) $(INCLUDES) $<

TEST_SHA1: test_sha1.c sha1.o
	$(CC) $(CFLAGS) -o $@ $^
