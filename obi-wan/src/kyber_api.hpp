#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>

// extern "C" declarations for Kyber ref encaps/decaps (used by obi-wan)

extern "C" {

int pqcrystals_kyber512_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber512_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber512_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int pqcrystals_kyber1024_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber1024_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

} // extern "C"

struct KyberKEMSizes {
    size_t pk_bytes;
    size_t sk_bytes;
    size_t ct_bytes;
    size_t ss_bytes = 32;
};

inline KyberKEMSizes kyber_kem_sizes(int level) {
    switch (level) {
        case 512:  return {800,  1632, 768,  32};
        case 768:  return {1184, 2400, 1088, 32};
        case 1024: return {1568, 3168, 1568, 32};
        default:   throw std::invalid_argument("Invalid Kyber level: must be 512, 768, or 1024");
    }
}
