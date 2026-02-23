#pragma once
#include "kyber_api.hpp"
#include <vector>
#include <cstdint>

namespace kyber {

void keygen(const KyberParams& params,
            std::vector<uint8_t>& pk,
            std::vector<uint8_t>& sk);

void encaps(const KyberParams& params,
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss);

void decaps(const KyberParams& params,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss);

} // namespace kyber
