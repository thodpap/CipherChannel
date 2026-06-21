CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
LDFLAGS ?=

# mbedTLS 3.x ships three separate libraries; always link all three.
MBEDTLS_CFLAGS := $(shell pkg-config --cflags mbedtls 2>/dev/null)
MBEDTLS_LIBS   := -lmbedtls -lmbedx509 -lmbedcrypto

ALL_CFLAGS  = $(CFLAGS) $(MBEDTLS_CFLAGS)
ALL_LDFLAGS = $(LDFLAGS) $(MBEDTLS_LIBS)

TARGET = dtls_client

.PHONY: all clean

all: $(TARGET)

$(TARGET): dtls_client.c
	$(CC) $(ALL_CFLAGS) -o $@ $< $(ALL_LDFLAGS)

clean:
	rm -f $(TARGET)
