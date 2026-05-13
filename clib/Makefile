# age-otp C Library — Simple Makefile

CARGO  ?= cargo
CC     ?= gcc
CFLAGS ?= -Wall -Wextra -std=c11 -O2
LDFLAGS ?= -Wl,-rpath,'$$ORIGIN' -lpthread -lm -ldl

LIB_SRC := ../target/release/libage_otp.so
LIB     := libage_otp.so
HDR     := age-otp.h
EXE     := example

.PHONY: all lib example test clean

all: lib example

lib:
	$(CARGO) build --release --manifest-path ../Cargo.toml
	cp $(LIB_SRC) .

example: lib $(HDR)
	$(CC) $(CFLAGS) -I. -o $(EXE) example.c -L. -lage_otp $(LDFLAGS)

test: example
	./$(EXE)

clean:
	rm -f $(LIB) $(EXE)
	$(CARGO) clean --manifest-path ../Cargo.toml