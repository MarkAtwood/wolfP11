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

/* wp11_test_threads_main.c -- thread-safety test suite main driver */
#ifdef WOLFP11_CFG_TEST
#include "test/wp11_test_pkcs11_threads.h"
#include <stdio.h>

int main(void) {
    int failures = 0;
    failures += wp11_test_pkcs11_threads();
    if (failures == 0) {
        printf("All thread tests passed.\n");
        return 0;
    } else {
        printf("%d thread test(s) FAILED.\n", failures);
        return 1;
    }
}
#endif /* WOLFP11_CFG_TEST */
