#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace mcs {

struct SlhDsaKeys {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

SlhDsaKeys keygen_slhdsa(const std::string& alg_name);

} // namespace mcs
