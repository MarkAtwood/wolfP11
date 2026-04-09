CC      = cc

# wolfSSL -- prefer a local install (with wolfprovider; allows RSA < 2048) over
# the system-wide one.  If $(WOLFSSL_LOCAL)/lib/pkgconfig/wolfssl.pc exists it
# is used; otherwise pkg-config falls back to the system path.
WOLFSSL_LOCAL  ?= $(HOME)/wolfssl-install/usr/local
_WOLFSSL_PC     = $(WOLFSSL_LOCAL)/lib/pkgconfig/wolfssl.pc
_WOLFSSL_PCDIR  = $(if $(wildcard $(_WOLFSSL_PC)),PKG_CONFIG_PATH=$(WOLFSSL_LOCAL)/lib/pkgconfig,)
WOLFSSL_CFLAGS  = $(shell $(_WOLFSSL_PCDIR) pkg-config --cflags wolfssl)
WOLFSSL_LIBS    = $(shell $(_WOLFSSL_PCDIR) pkg-config --libs wolfssl)
WOLFSSL_LIBDIR  = $(shell $(_WOLFSSL_PCDIR) pkg-config --variable=libdir wolfssl)

# wolfP11-v3c: security hardening flags (always-on per project policy).
#   -O2                     required for _FORTIFY_SOURCE to detect overflows
#   -fstack-protector-strong  stack canaries; requires GCC >= 4.9 / any clang
#   -D_FORTIFY_SOURCE=2     runtime bounds on libc string/memory calls
#   -Wformat=2              stricter format-string checking beyond -Wall
#   -Wformat-security       warn on format strings that may become security issues
CFLAGS  = -Wall -Wextra -Werror -std=c99 -fPIC \
          -O2 \
          -fstack-protector-strong \
          -D_FORTIFY_SOURCE=2 \
          -Wformat=2 -Wformat-security \
          -I. \
          -I/usr/include/p11-kit-1 \
          -DWOLFP11_CFG_USB_BACKEND \
          $(WOLFSSL_CFLAGS) \
          $(shell pkg-config --cflags libusb-1.0)
# wolfP11-v3c: link-time hardening.
#   -z relro   make GOT read-only after dynamic linking (partial RELRO)
#   -z now     resolve all symbols at load time; combine with relro = full RELRO
#   -z noexecstack  mark the stack as non-executable (NX)
LDFLAGS = $(shell pkg-config --libs libusb-1.0) -lpthread \
          -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

# wolfP11-v3c: PIE flags for the CLI executable.
# -fPIC (already in CFLAGS) is sufficient for the shared library; the CLI
# binary needs separate -fPIE/-pie to be position-independent.
EXEFLAGS = -fPIE -pie

# wolfP11-7z5: installation paths.
PREFIX  ?= /usr/local
DESTDIR ?=

WOLFSSL_DIR ?= $(HOME)/wolfssl
WOLFHSM_DIR ?= $(HOME)/wolfHSM

SRCS = src/wp11_pkcs11.c \
       src/wp11_token_db.c \
       src/wp11_ccid.c \
       src/wp11_proto_piv.c \
       src/wp11_proto_openpgp.c \
       src/wp11_backend_soft.c \
       src/wp11_backend_usb.c

# wolfHSM backend is opt-in: make WOLFHSM=1 [WOLFHSM_DIR=path]
#
# Required compile flags explained:
#   WOLFP11_CFG_WOLFHSM_BACKEND  -- enables wp11_backend_wolfhsm.c
#   WOLFHSM_CFG_ENABLE_CLIENT    -- gates wh_Client_* API in wh_client_crypto.c;
#                                  without this, all wolfHSM client functions are
#                                  omitted and the link fails with undefined refs
#   WOLFHSM_CFG_NO_SYS_TIME      -- suppresses the WOLFHSM_CFG_PORT_GETTIME
#                                  requirement in wh_settings.h; wolfP11 does not
#                                  use wolfHSM's internal timing/benchmark code
#   HAVE_ANONYMOUS_INLINE_AGGREGATES=1
#                                -- wolfssl/wolfcrypt/types.h auto-sets this for
#                                  C11+, but not for -std=c99 (even though GCC
#                                  and Clang support anonymous aggregates as an
#                                  extension in C99 mode); wh_settings.h asserts
#                                  the macro is set and errors out without it
#
# Link note: -lwolfhsm requires a separately built wolfHSM static/shared library.
# Run 'make lib' in ~/wolfHSM (branch wolfp11-lib-build or later) to produce
# $(WOLFHSM_DIR)/build/libwolfhsm.so and libwolfhsm.a before running this.
ifdef WOLFHSM
SRCS    += src/wp11_backend_wolfhsm.c \
           $(WOLFHSM_DIR)/port/posix/posix_transport_shm.c \
           $(WOLFHSM_DIR)/port/posix/posix_transport_tcp.c
CFLAGS  += -DWOLFP11_CFG_WOLFHSM_BACKEND \
           -DWOLFHSM_CFG_ENABLE_CLIENT \
           -DWOLFHSM_CFG_NO_SYS_TIME \
           -DHAVE_ANONYMOUS_INLINE_AGGREGATES=1 \
           -D_POSIX_C_SOURCE=200809L \
           -I$(WOLFHSM_DIR)
LDFLAGS += -L$(WOLFHSM_DIR)/build -lwolfhsm -Wl,-rpath,$(WOLFHSM_DIR)/build
endif

# USB flash drive keystore backend is opt-in
ifdef USBFLASH
SRCS    += src/wp11_keystore.c \
           src/wp11_backend_usb_flash.c
CFLAGS  += -DWOLFP11_CFG_USB_FLASH_BACKEND
KS_OPS_SRC = src/wp11_backend_keystore.c
endif

# Filesystem directory keystore backend is opt-in (FSDIR=1)
# Watches a flat directory for .p11k files; uses the same AES-GCM keystore
# format as the USB flash backend.  Requires inotify (Linux only).
ifdef FSDIR
SRCS    += src/wp11_keystore.c \
           src/wp11_backend_fsdir.c
CFLAGS  += -DWOLFP11_CFG_FSDIR_BACKEND
KS_OPS_SRC = src/wp11_backend_keystore.c
endif

# Add shared keystore ops exactly once (both backends set KS_OPS_SRC).
ifdef KS_OPS_SRC
SRCS += $(KS_OPS_SRC)
endif

BUILD        = build
LIB          = $(BUILD)/libwolfp11.so
CLI          = $(BUILD)/wp11
TEST         = $(BUILD)/wp11_test
TEST_THREADS = $(BUILD)/wp11_test_threads

PKCS11TEST_DIR ?= $(HOME)/pkcs11test

.PHONY: all test test-threads pkcs11test clean scan install uninstall test-asan test-ubsan

all: $(BUILD) $(LIB) $(CLI)

$(BUILD):
	mkdir -p $(BUILD)

$(LIB): $(SRCS)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) $(WOLFSSL_LIBS) -Wl,-rpath,$(WOLFSSL_LIBDIR)

$(CLI): src/cli/wp11_cli.c $(LIB)
	$(CC) $(CFLAGS) $(EXEFLAGS) -o $@ $< -L$(BUILD) -lwolfp11 $(LDFLAGS)

TEST_SRCS = test/wp11_test.c \
            test/wp11_test_token_db.c \
            test/wp11_test_ccid.c \
            test/wp11_test_piv.c \
            test/wp11_test_openpgp.c \
            test/wp11_test_pkcs11.c \
            test/wp11_test_keystore.c \
            test/wp11_test_backend_soft.c \
            test/wp11_test_fsdir.c

# wolfHSM backend test sources (opt-in with WOLFHSM=1).
# The server sources are compiled separately with WOLFHSM_CFG_ENABLE_SERVER so
# that the in-process server thread is available in the test binary.
# libwolfhsm.a was built without that flag; its server .o stubs define no
# symbols, so there are no duplicate-symbol conflicts at link time.
ifdef WOLFHSM
TEST_SRCS         += test/wp11_test_backend_wolfhsm.c \
                     $(WOLFHSM_DIR)/src/wh_transport_mem.c \
                     $(WOLFHSM_DIR)/src/wh_comm.c \
                     $(WOLFHSM_DIR)/src/wh_server.c \
                     $(WOLFHSM_DIR)/src/wh_server_counter.c \
                     $(WOLFHSM_DIR)/src/wh_server_customcb.c \
                     $(WOLFHSM_DIR)/src/wh_server_crypto.c \
                     $(WOLFHSM_DIR)/src/wh_server_keystore.c \
                     $(WOLFHSM_DIR)/src/wh_server_nvm.c
# AES_BLOCK_SIZE is suppressed by OPENSSL_COEXIST in this wolfSSL build;
# restore it for wolfHSM server sources that rely on the alias.
TEST_CFLAGS_EXTRA  = -DWOLFHSM_CFG_ENABLE_SERVER -DAES_BLOCK_SIZE=16
endif

ifdef FSDIR
TEST_SRCS += test/wp11_test_backend_fsdir.c
endif

ifdef USBFLASH
TEST_SRCS += test/wp11_test_backend_usb_flash.c
endif

$(TEST): $(TEST_SRCS) $(SRCS)
	$(CC) $(CFLAGS) $(TEST_CFLAGS_EXTRA) -DWOLFP11_CFG_TEST -o $@ $^ $(LDFLAGS) $(WOLFSSL_LIBS) -Wl,-rpath,$(WOLFSSL_LIBDIR)

test: $(BUILD) $(TEST)
	$(TEST)

TEST_THREADS_SRCS = test/wp11_test_threads_main.c \
                    test/wp11_test_pkcs11_threads.c

$(TEST_THREADS): $(TEST_THREADS_SRCS) $(SRCS)
	$(CC) $(CFLAGS) -DWOLFP11_CFG_TEST -DWOLFP11_CFG_TEST_THREADS \
	    -o $@ $^ $(LDFLAGS) $(WOLFSSL_LIBS) -Wl,-rpath,$(WOLFSSL_LIBDIR)

test-threads: $(BUILD) $(TEST_THREADS)
	$(TEST_THREADS)

# pkcs11test -- run google/pkcs11test conformance suite against the soft backend.
#
# Requires:
#   make USBFLASH=1 pkcs11test        (keystore support needed for PIN init)
#   $(HOME)/pkcs11test/pkcs11test     (pre-built; override with PKCS11TEST_DIR)
#   pkcs11-tool                       (opensc package; used to initialise the PIN)
#
# A temporary keystore is created in /tmp/wp11_pkcs11test/soft.p11k and
# destroyed on exit.  Use WOLFP11_SOFT_KEYSTORE_PATH to override.
PKCS11TEST_KS ?= /tmp/wp11_pkcs11test/soft.p11k
PKCS11TEST_PIN ?= pkcs11testpin
pkcs11test: $(BUILD) $(LIB)
	@echo "--- wolfP11 pkcs11test conformance run ---"
	mkdir -p $(dir $(PKCS11TEST_KS))
	rm -f $(PKCS11TEST_KS)
	WOLFP11_SOFT_KEYSTORE_PATH=$(PKCS11TEST_KS) \
	    LD_LIBRARY_PATH=$(WOLFSSL_LIBDIR) \
	    pkcs11-tool --module $(LIB) \
	    --init-pin --slot 0 --so-pin $(PKCS11TEST_PIN) --new-pin $(PKCS11TEST_PIN)
	WOLFP11_SOFT_KEYSTORE_PATH=$(PKCS11TEST_KS) \
	    LD_LIBRARY_PATH=$(BUILD):$(WOLFSSL_LIBDIR) \
	    $(PKCS11TEST_DIR)/pkcs11test -m libwolfp11.so -l $(BUILD) \
	    -s 0 -u $(PKCS11TEST_PIN) -o $(PKCS11TEST_PIN) ; \
	    RES=$$? ; \
	    rm -f $(PKCS11TEST_KS) ; \
	    exit $$RES

clean:
	rm -rf $(BUILD)

scan:
	scan-build $(MAKE) all

# wolfP11-7z5: install/uninstall targets.
install: all
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 0755 $(LIB) $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(CLI) $(DESTDIR)$(PREFIX)/bin/
	install -d $(DESTDIR)$(PREFIX)/include/wolfp11
	install -m 0644 wolfp11/*.h $(DESTDIR)$(PREFIX)/include/wolfp11/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/libwolfp11.so
	rm -f $(DESTDIR)$(PREFIX)/bin/wp11
	rm -rf $(DESTDIR)$(PREFIX)/include/wolfp11

# wolfP11-0vb: sanitizer test builds.
# wolfssl itself is not rebuilt with sanitizers; wolfP11 code is instrumented.
# -fno-sanitize-recover=all causes the test binary to abort on any violation.
test-asan: clean
	$(MAKE) CFLAGS="$(CFLAGS) -fsanitize=address,undefined -fno-sanitize-recover=all" \
	        LDFLAGS="$(LDFLAGS) -fsanitize=address,undefined" \
	        $(TEST)
	$(TEST)

test-ubsan: clean
	$(MAKE) CFLAGS="$(CFLAGS) -fsanitize=undefined -fno-sanitize-recover=all" \
	        LDFLAGS="$(LDFLAGS) -fsanitize=undefined" \
	        $(TEST)
	$(TEST)

# wolfP11-ehr: header dependency tracking requires two-step (.c -> .o -> .so)
# compilation so gcc -MMD can produce per-file .d files.  The current
# single-invocation build does not support this; 'make clean' is required
# after modifying any wolfp11/*.h header.
