#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace slhdsa_sig {

// Returns true if alg_name starts with "SLH-DSA"
bool is_slhdsa_sig(const std::string& alg_name);

// Returns the fixed signature size in bytes for the given SLH-DSA algorithm.
size_t sig_bytes(const std::string& alg_name);

// Sign msg with sk; fills sig_out with the signature.
void sign(const std::string& alg_name,
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          std::vector<uint8_t>& sig_out);

// Verify sig against pk and msg. Returns true if valid.
bool verify(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const std::vector<uint8_t>& sig);

} // namespace slhdsa_sig
