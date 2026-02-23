#pragma once
#include "dilithium_api.hpp"
#include <vector>
#include <cstdint>

namespace dilithium {

void keygen(const DilithiumParams& params,
            std::vector<uint8_t>& pk,
            std::vector<uint8_t>& sk);

void sign(const DilithiumParams& params,
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          const uint8_t* ctx, size_t ctxlen,
          std::vector<uint8_t>& sig);

// Returns true if valid, false if invalid.
bool verify(const DilithiumParams& params,
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const uint8_t* ctx, size_t ctxlen,
            const std::vector<uint8_t>& sig);

} // namespace dilithium
