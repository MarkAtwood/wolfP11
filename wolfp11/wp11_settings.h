/* wolfP11
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfP11.
 *
 * wolfP11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfP11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * For a commercial license, contact wolfSSL Inc. at licensing@wolfssl.com.
 */

/* wp11_settings.h -- wolfP11 compile-time configuration
 *
 * All macros use the WOLFP11_CFG_ prefix.
 * Defaults are defined here; override via -D on the compiler command line.
 */

#ifndef WOLFP11_SETTINGS_H
#define WOLFP11_SETTINGS_H

/* Maximum number of simultaneously open sessions */
#ifndef WOLFP11_CFG_MAX_SESSIONS
#define WOLFP11_CFG_MAX_SESSIONS  8
#endif
/* wolfP11-qjo: enforce sane range at compile time.  0 makes the session array
 * zero-length (UB); very large values exhaust BSS silently. */
#if WOLFP11_CFG_MAX_SESSIONS < 1 || WOLFP11_CFG_MAX_SESSIONS > 256
#error "WOLFP11_CFG_MAX_SESSIONS must be in the range [1, 256]"
#endif

/* Maximum number of slots (soft slot + USB slots) */
#ifndef WOLFP11_CFG_MAX_SLOTS
#define WOLFP11_CFG_MAX_SLOTS  16
#endif
/* wolfP11-qjo: same rationale as MAX_SESSIONS above. */
#if WOLFP11_CFG_MAX_SLOTS < 1 || WOLFP11_CFG_MAX_SLOTS > 256
#error "WOLFP11_CFG_MAX_SLOTS must be in the range [1, 256]"
#endif

/* Enable USB hardware token backend (requires libusb) */
/* #define WOLFP11_CFG_USB_BACKEND */

/* Enable wolfHSM server backend (requires wolfHSM) */
/* #define WOLFP11_CFG_WOLFHSM_BACKEND */

/* wolfHSM server address string (format depends on transport layer, e.g.
 * a POSIX-SHM key, a TCP "host:port", or a socket path).
 * Runtime env var WOLFP11_WOLFHSM_SERVER_ADDR takes precedence.
 * NULL (the default) means no wolfHSM slot is created at C_Initialize. */
#ifndef WOLFP11_CFG_WOLFHSM_SERVER_ADDR
#define WOLFP11_CFG_WOLFHSM_SERVER_ADDR  NULL
#endif

/* wolfHSM token label shown by C_GetTokenInfo.
 * Runtime env var WOLFP11_WOLFHSM_LABEL takes precedence. */
#ifndef WOLFP11_CFG_WOLFHSM_LABEL
#define WOLFP11_CFG_WOLFHSM_LABEL  "wolfHSM Server"
#endif

/* Enable OpenPGP card protocol (depends on USB backend) */
#ifndef WOLFP11_CFG_OPENPGP
#define WOLFP11_CFG_OPENPGP  1
#endif

/* Guard USB-dependent tests */
/* #define WOLFP11_CFG_TEST_USB */

/* Library version string */
#define WOLFP11_VERSION_STRING  "wolfP11 0.1.0"

/* Enable USB flash drive encrypted keystore backend */
/* #define WOLFP11_CFG_USB_FLASH_BACKEND */

/* Directory to watch for .p11k keystore files (inotify-based USB detection).
 * udisks2 mounts USB drives as /run/media/$USER/<label>/ on desktop Linux.
 * Override with -DWOLFP11_CFG_USB_FLASH_WATCH_DIR='"your/path"' */
#ifndef WOLFP11_CFG_USB_FLASH_WATCH_DIR
#define WOLFP11_CFG_USB_FLASH_WATCH_DIR "/run/media"
#endif

/* Enable filesystem directory keystore backend (inotify-based; flat dir).
 * When enabled, wolfP11 watches WOLFP11_CFG_FSDIR_PATH for .p11k files and
 * creates a PKCS#11 slot for each one found. */
/* #define WOLFP11_CFG_FSDIR_BACKEND */

/* Directory to watch for .p11k keystore files (FSDIR backend).
 * Override at runtime with the WOLFP11_FSDIR_PATH environment variable.
 * Override at compile time with -DWOLFP11_CFG_FSDIR_PATH='"your/path"' */
#ifndef WOLFP11_CFG_FSDIR_PATH
#define WOLFP11_CFG_FSDIR_PATH "/var/lib/wolfp11"
#endif

/* Path for the soft-token persistent keystore file.
 * NULL (the default) means use $HOME/.wolfp11/soft.p11k at runtime.
 * Override the runtime env var WOLFP11_SOFT_KEYSTORE_PATH takes precedence
 * over this compile-time default.
 * Override with -DWOLFP11_CFG_SOFT_KEYSTORE_PATH='"/path/to/soft.p11k"' */
#ifndef WOLFP11_CFG_SOFT_KEYSTORE_PATH
#define WOLFP11_CFG_SOFT_KEYSTORE_PATH  NULL
#endif

#endif /* WOLFP11_SETTINGS_H */
