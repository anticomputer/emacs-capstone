EMACS_SRC 	?= $(HOME)/emacs_src/emacs
CAPSTONE_INC	?= /usr/include/capstone
EMACS 		?= emacs
CC      	= gcc
LD      	= gcc
LDFLAGS		= -L .
CFLAGS 		= -std=gnu99 -ggdb3 -O2 -Wall -fPIC -I$(EMACS_SRC)/src -I$(CAPSTONE_INC)

all: test

capstone-core.so: capstone-core.o
	$(LD) -shared $(LDFLAGS) -o $@ $^ -lcapstone

capstone-core.o: src/capstone-core.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	-rm -f capstone-core.o capstone-core.so

# make sure libcapstone is actually installed on your system when using normally
test: capstone-core.so
	$(EMACS) -Q -batch -L . -l src/test/test.el -f ert-run-tests-batch-and-exit
