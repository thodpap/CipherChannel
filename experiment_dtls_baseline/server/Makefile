CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
LDFLAGS ?=

# Try pkg-config first; fall back to well-known Fedora/Debian paths
# mbedTLS 3.x ships three separate libraries; always link all three.
MBEDTLS_CFLAGS := $(shell pkg-config --cflags mbedtls 2>/dev/null)
MBEDTLS_LIBS   := -lmbedtls -lmbedx509 -lmbedcrypto

ALL_CFLAGS  = $(CFLAGS) $(MBEDTLS_CFLAGS)
ALL_LDFLAGS = $(LDFLAGS) $(MBEDTLS_LIBS)

TARGET = dtls_server

.PHONY: all clean

all: $(TARGET)

$(TARGET): dtls_server.c
	$(CC) $(ALL_CFLAGS) -o $@ $< $(ALL_LDFLAGS)

clean:
	rm -f $(TARGET)
