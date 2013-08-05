#!/usr/bin/make
# -*- makefile -*-

KEYS = keys/a.pem keys/b.pem
PUBKEYS = $(patsubst keys/%.pem,keys/%,$(KEYS))
SIGS = signatures/1a.b64 signatures/1b.b64 signatures/2a.b64 signatures/2b.b64

CFLAGS = -O2 -Wall -pedantic
LIBS = -lssl -lcrypto

all : $(PUBKEYS) $(KEYS) $(DATA) $(SIGS)

convert_pkcs1 : convert_pkcs1.c
	gcc $(CFLAGS) $< $(LIBS) -o $@

keys/%.pem :
	openssl genrsa 1024 > $@

keys/% : keys/%.pem convert_pkcs1
	openssl rsa -pubout < $< | ./convert_pkcs1 > $@

data/2.b64 :
	dd if=/dev/urandom bs=1024 count=1 | base64 > $@

data/% : data/%.b64
	base64 -d < $< > $@

signatures/%a : data/% keys/a.pem data/%
	openssl sha1 -sign keys/a.pem < $< > $@
signatures/%b : data/% keys/a.pem data/%
	openssl sha1 -sign keys/b.pem < $< > $@

signatures/%.b64 : signatures/%
	base64 < $< > $@

clean :
	rm -f $(KEYS) $(PUBKEYS) $(DATA) $(SIGS) convert_pkcs1

.PHONY : all clean
.DEFAULT_GOAL := all
