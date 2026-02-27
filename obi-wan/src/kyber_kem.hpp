#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace kyber_kem {

// Detect Kyber level from alg_name ("Kyber512" → 512, etc.)
int level_from_alg(const std::string& alg_name);

// Encapsulate: generate ciphertext ct and shared secret ss against public key pk.
// level: 512, 768, or 1024
void encaps(int level,
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct_out,
            std::vector<uint8_t>& ss_out);

// Decapsulate: recover shared secret ss from ciphertext ct and secret key sk.
void decaps(int level,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out);

} // namespace kyber_kem
