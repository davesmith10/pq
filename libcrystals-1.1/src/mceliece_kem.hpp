#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace mceliece_kem {

// Encapsulate: generate ciphertext ct and shared secret ss against public key pk.
// param_set: "mceliece348864f", "mceliece460896f", "mceliece6688128f",
//            "mceliece6960119f", or "mceliece8192128f"
void encaps(const std::string& param_set,
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct_out,
            std::vector<uint8_t>& ss_out);

// Decapsulate: recover shared secret ss from ciphertext ct and secret key sk.
void decaps(const std::string& param_set,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out);

} // namespace mceliece_kem
