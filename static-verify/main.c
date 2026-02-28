#include <stdio.h>

int test_kyber(void);
int test_dilithium(void);

int main(void)
{
    int ok = 1;

    ok &= test_kyber();
    ok &= test_dilithium();

    if (ok) {
        printf("All tests passed.\n");
        return 0;
    } else {
        printf("One or more tests FAILED.\n");
        return 1;
    }
}
