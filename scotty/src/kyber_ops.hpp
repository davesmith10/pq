#pragma once
#include <vector>
#include <cstdint>

namespace kyber {

// Ref-only keygen. level must be 512, 768, or 1024.
void keygen(int level, std::vector<uint8_t>& pk, std::vector<uint8_t>& sk);

} // namespace kyber
