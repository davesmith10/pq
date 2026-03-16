#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace mcs {

struct McElieceKeys {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

McElieceKeys keygen_mceliece(const std::string& param_set);

} // namespace mcs
