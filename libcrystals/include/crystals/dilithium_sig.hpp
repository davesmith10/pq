#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace dilithium_sig {

// Returns true if alg_name is a Dilithium PQ signature algorithm
bool is_pq_sig(const std::string& alg_name);

// Returns the Dilithium mode (2, 3, or 5) from alg_name ("Dilithium2/3/5")
int mode_from_alg(const std::string& alg_name);

// Returns the expected fixed signature size for the given mode
size_t sig_bytes_for_mode(int mode);

// Sign msg with sk; writes sig to sig_out (size = sig_bytes_for_mode(mode))
void sign(int mode,
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          std::vector<uint8_t>& sig_out);

// Verify sig over msg with pk; returns true if valid
bool verify(int mode,
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const std::vector<uint8_t>& sig);

} // namespace dilithium_sig
