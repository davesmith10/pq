#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace ec_sig {

// Returns true if alg_name is a supported classical signature algorithm
// ("Ed25519", "ECDSA P-256", "ECDSA P-384", "ECDSA P-521")
bool is_classical_sig(const std::string& alg_name);

// Returns the fixed signature byte size for alg_name:
//   Ed25519:    64 bytes
//   ECDSA P-256: 64 bytes  (P1363: 32+32)
//   ECDSA P-384: 96 bytes  (P1363: 48+48)
//   ECDSA P-521: 132 bytes (P1363: 66+66)
size_t sig_bytes(const std::string& alg_name);

// Sign msg with classical sk; writes fixed-size P1363/raw signature to sig_out
void sign(const std::string& alg_name,
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          std::vector<uint8_t>& sig_out);

// Verify sig over msg with classical pk; returns true if valid
bool verify(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const std::vector<uint8_t>& sig);

} // namespace ec_sig
