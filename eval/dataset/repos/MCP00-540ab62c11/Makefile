CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Iinclude

all: app

app: src/main.c src/util.c include/util.h
	$(CC) $(CFLAGS) -o $@ src/main.c src/util.c

clean:
	rm -f app
