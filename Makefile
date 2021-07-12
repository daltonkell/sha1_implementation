CC=gcc
INCLUDE=-I./
#DEBUG=-DDEBUG=1
CFLAGS=-ggdb $(DEBUG)

sha1.o: sha1.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

test_sha1.o: test_sha1.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

TEST_SHA1: test_sha1.o sha1.o
	$(CC) -o $@ $^

clean:
	rm test_sha1.o sha1.o
