VERSION = "0.5 (Oltmann variant)"

# flags
CC = cc
CFLAGS = -std=c99 -Wall -Wextra
CPPFLAGS = -DVERSION=\"$(VERSION)\" -D_XOPEN_SOURCE=700
LDFLAGS =

# paths
PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

# Arch Linux Testing
# LIB_PATH=/lib/libressl
# LIBTLS_PKGCONF_PATH = /usr/lib/libressl/pkgconfig/
# CFLAGS := $(CFLAGS) `PKG_CONFIG_PATH=$(LIBTLS_PKGCONF_PATH) pkg-config --cflags libtls`
# FLAGS = `PKG_CONFIG_PATH=$(LIBTLS_PKGCONF_PATH) pkg-config --libs libtls`

# Any system that is using LibreSSL as the default SSL provider
LDLIBS = -ltls
