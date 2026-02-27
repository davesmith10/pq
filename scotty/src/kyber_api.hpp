#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>

// ── extern "C" declarations for Kyber ref keypair functions ──────────────────

extern "C" {

int pqcrystals_kyber512_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber1024_ref_keypair(uint8_t *pk, uint8_t *sk);

} // extern "C"

struct KyberSizes {
    size_t pk_bytes;
    size_t sk_bytes;
};

inline KyberSizes kyber_sizes(int level) {
    switch (level) {
        case 512:  return {800,  1632};
        case 768:  return {1184, 2400};
        case 1024: return {1568, 3168};
        default:   throw std::invalid_argument("Invalid Kyber level: must be 512, 768, or 1024");
    }
}
