#pragma once
#include <vector>
#include <cstdint>

namespace ec {

enum class Algorithm {
    X25519,
    Ed25519,
    P256,
    P384,
    P521
};

struct KeyPair {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

KeyPair keygen(Algorithm alg);

} // namespace ec
