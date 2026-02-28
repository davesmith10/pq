#include <stdint.h>
#include <stdio.h>

/* Forward-declare the three keypair functions directly to avoid CRYPTO_* macro
   collisions if both kyber and dilithium api.h were included in one TU. */
int pqcrystals_dilithium2_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium5_ref_keypair(uint8_t *pk, uint8_t *sk);

int test_dilithium(void)
{
    int ok = 1;
    int rc;

    /* Dilithium2: pk=1312 sk=2560 */
    {
        uint8_t pk[1312], sk[2560];
        rc = pqcrystals_dilithium2_ref_keypair(pk, sk);
        printf("Dilithium2 keygen: %s\n", rc == 0 ? "OK" : "FAIL");
        if (rc != 0) ok = 0;
    }

    /* Dilithium3: pk=1952 sk=4032 */
    {
        uint8_t pk[1952], sk[4032];
        rc = pqcrystals_dilithium3_ref_keypair(pk, sk);
        printf("Dilithium3 keygen: %s\n", rc == 0 ? "OK" : "FAIL");
        if (rc != 0) ok = 0;
    }

    /* Dilithium5: pk=2592 sk=4896 */
    {
        uint8_t pk[2592], sk[4896];
        rc = pqcrystals_dilithium5_ref_keypair(pk, sk);
        printf("Dilithium5 keygen: %s\n", rc == 0 ? "OK" : "FAIL");
        if (rc != 0) ok = 0;
    }

    return ok;
}
