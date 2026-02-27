#pragma once
#include <vector>
#include <cstdint>

namespace dilithium {

// Ref-only keygen. mode must be 2, 3, or 5.
void keygen(int mode, std::vector<uint8_t>& pk, std::vector<uint8_t>& sk);

} // namespace dilithium
