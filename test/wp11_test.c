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
    if (failures == 0) {
        printf("All tests passed.\n");
        return 0;
    } else {
        printf("%d test(s) FAILED.\n", failures);
        return 1;
    }
}
#endif /* WOLFP11_CFG_TEST */
