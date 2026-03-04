#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace ec_kem {

// Detect EC KEM algorithm from alg_name ("X25519", "P-256", "P-384", "P-521")
// Returns true if alg_name is a supported KEM-classical algorithm.
bool is_classical_kem(const std::string& alg_name);

// Encapsulate: generate ephemeral keypair, perform ECDH with recipient public key.
// ct_out = ephemeral public key bytes (CT_classical)
// ss_out = ECDH shared secret
void encaps(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct_out,
            std::vector<uint8_t>& ss_out);

// Decapsulate: recover shared secret from CT (ephemeral pk) and recipient secret key.
void decaps(const std::string& alg_name,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out);

} // namespace ec_kem
