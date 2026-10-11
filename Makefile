CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lcrypto

.PHONY: all clean check

all: cask

cask: cask.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 $(LDFLAGS) -o $@ $< $(LDLIBS)

check: cask
	./cask --version
	./cask --help

clean:
	rm -f cask
