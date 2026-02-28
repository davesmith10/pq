#include <stdint.h>
#include <stdio.h>

/* Forward-declare the three keypair functions directly to avoid CRYPTO_* macro
   collisions if both kyber and dilithium api.h were included in one TU. */
int pqcrystals_kyber512_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber1024_ref_keypair(uint8_t *pk, uint8_t *sk);

int test_kyber(void)
{
    int ok = 1;
    int rc;

    /* Kyber512: pk=800 sk=1632 */
    {
        uint8_t pk[800], sk[1632];
        rc = pqcrystals_kyber512_ref_keypair(pk, sk);
        printf("Kyber512  keygen: %s\n", rc == 0 ? "OK" : "FAIL");
        if (rc != 0) ok = 0;
    }

    /* Kyber768: pk=1184 sk=2400 */
    {
        uint8_t pk[1184], sk[2400];
        rc = pqcrystals_kyber768_ref_keypair(pk, sk);
        printf("Kyber768  keygen: %s\n", rc == 0 ? "OK" : "FAIL");
        if (rc != 0) ok = 0;
    }

    /* Kyber1024: pk=1568 sk=3168 */
    {
        uint8_t pk[1568], sk[3168];
        rc = pqcrystals_kyber1024_ref_keypair(pk, sk);
        printf("Kyber1024 keygen: %s\n", rc == 0 ? "OK" : "FAIL");
        if (rc != 0) ok = 0;
    }

    return ok;
}
