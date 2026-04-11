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

/* wp11_test.c -- wolfP11 test suite main driver */
#ifdef WOLFP11_CFG_TEST
#include "test/wp11_test_token_db.h"
#include "test/wp11_test_ccid.h"
#include "test/wp11_test_piv.h"
#include "test/wp11_test_openpgp.h"
#include "test/wp11_test_pkcs11.h"
#include "test/wp11_test_keystore.h"
#include "test/wp11_test_backend_soft.h"
#ifdef WOLFP11_CFG_WOLFHSM_BACKEND
#include "test/wp11_test_backend_wolfhsm.h"
#endif
#include "test/wp11_test_fsdir.h"
#ifdef WOLFP11_CFG_FSDIR_BACKEND
#include "test/wp11_test_backend_fsdir.h"
#endif
#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
#include "test/wp11_test_backend_usb_flash.h"
#endif
#include <stdio.h>

int main(void) {
    int failures = 0;
    failures += wp11_test_token_db();
    failures += wp11_test_ccid();
    failures += wp11_test_piv();
    failures += wp11_test_openpgp();
    failures += wp11_test_pkcs11();
    failures += wp11_test_keystore();
    failures += wp11_test_backend_soft();
#ifdef WOLFP11_CFG_WOLFHSM_BACKEND
    failures += wp11_test_backend_wolfhsm();
#endif
    failures += wp11_test_fsdir();
#ifdef WOLFP11_CFG_FSDIR_BACKEND
    failures += wp11_test_backend_fsdir();
#endif
#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    failures += wp11_test_backend_usb_flash();
#endif
    if (failures == 0) {
        printf("All tests passed.\n");
        return 0;
    } else {
        printf("%d test(s) FAILED.\n", failures);
        return 1;
    }
}
#endif /* WOLFP11_CFG_TEST */
