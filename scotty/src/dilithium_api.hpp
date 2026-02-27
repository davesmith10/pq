#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>

// ── extern "C" declarations for Dilithium ref keypair functions ───────────────

extern "C" {

int pqcrystals_dilithium2_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium5_ref_keypair(uint8_t *pk, uint8_t *sk);

} // extern "C"

struct DilithiumSizes {
    size_t pk_bytes;
    size_t sk_bytes;
};

inline DilithiumSizes dilithium_sizes(int mode) {
    switch (mode) {
        case 2: return {1312, 2560};
        case 3: return {1952, 4032};
        case 5: return {2592, 4896};
        default: throw std::invalid_argument("Invalid Dilithium mode: must be 2, 3, or 5");
    }
}
