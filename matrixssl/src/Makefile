#
#	Makefile for MatrixSSL library
#	Builds optimized shared library by default.
#	See comments below for building a debug library.
#	Copyright (c) PeerSec Networks, 2002-2004. All Rights Reserved.
#

CC      = gcc
STRIP   = strip
O       = .o
SO      = .so
E       =

LIBRARY	= libmatrixssl$(SO)

OBJECTS	= matrixSsl$(O) \
		sslEncode$(O) \
		sslDecode$(O) \
		sslv3$(O) \
		cipherSuite$(O)	\
		os/malloc$(O) \
		os/linux/linux$(O)	\
		crypto/peersec/arc4$(O) \
		crypto/peersec/asn1$(O) \
		crypto/peersec/base64$(O) \
		crypto/peersec/des3$(O) \
		crypto/peersec/md5$(O) \
		crypto/peersec/md2$(O) \
		crypto/peersec/mpi$(O) \
		crypto/peersec/rsa$(O) \
		crypto/peersec/sha1$(O)
#
#	Debug flags (Define MATRIXSSL_DEBUG in shell to build debug)
#	bash:	export MATRIXSSL_DEBUG=1
#			unset MATRIXSSL_DEBUG
#	tcsh:	setenv MATRIXSSL_DEBUG 1
#			unsetenv MATRIXSSL_DEBUG
#
ifdef MATRIXSSL_DEBUG
DFLAGS	= -g -Wall -DDEBUG
STRIP	= test
else
DFLAGS	= -Os
endif

#
#	Compile options
#
SHARED	= -shared
CFLAGS  = $(DFLAGS) -DLINUX
LDFLAGS = -nostdlib -lc -lpthread

#
#	Override variables for compilation on Mac OS X (Darwin)
#
ifeq ($(shell uname),Darwin)
CC	= cc
SO	= .dylib
SHARED	= -dynamiclib
CFLAGS += -DOSX -isystem -I/usr/include
LDFLAGS = -flat_namespace -install_name @executable_path/../src/$(LIBRARY)
STRIP = test
endif

#
#	Override variables for compilation on uClinux (example only)
#
ifdef UCLINUX
CC		= /opt/brcm/hndtools-mipsel-uclibc/bin/mipsel-uclibc-gcc
STRIP	= /opt/brcm/hndtools-mipsel-uclibc/bin/mipsel-uclibc-strip
endif

all: compile

compile: $(OBJECTS) $(LIBRARY)

#
# Manual dependencies
#
*.o: ../matrixSsl.h matrixInternal.h matrixConfig.h Makefile
os/*.o: matrixInternal.h matrixConfig.h Makefile os/osLayer.h
os/linux/*.o: matrixInternal.h matrixConfig.h Makefile os/osLayer.h
crypto/peersec/*.o: matrixInternal.h matrixConfig.h Makefile \
					crypto/cryptoLayer.h crypto/peersec/pscrypto.h
#
# Build the library
#
$(LIBRARY): $(OBJECTS)
	$(CC) $(SHARED) -o $@ $^ $(LDFLAGS)
	$(STRIP) $(LIBRARY)

#
#	Clean up all generated files
#
clean:
	rm -f $(LIBRARY) $(OBJECTS) 
