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
