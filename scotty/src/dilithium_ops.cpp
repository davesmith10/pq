#include "dilithium_ops.hpp"
#include "dilithium_api.hpp"
#include <stdexcept>

namespace dilithium {

void keygen(int mode, std::vector<uint8_t>& pk, std::vector<uint8_t>& sk) {
    auto sz = dilithium_sizes(mode);
    pk.resize(sz.pk_bytes);
    sk.resize(sz.sk_bytes);

    int rc = 0;
    switch (mode) {
        case 2: rc = pqcrystals_dilithium2_ref_keypair(pk.data(), sk.data()); break;
        case 3: rc = pqcrystals_dilithium3_ref_keypair(pk.data(), sk.data()); break;
        case 5: rc = pqcrystals_dilithium5_ref_keypair(pk.data(), sk.data()); break;
        default: throw std::logic_error("Invalid Dilithium mode in keygen");
    }
    if (rc != 0)
        throw std::runtime_error("Dilithium keygen failed (rc=" + std::to_string(rc) + ")");
}

} // namespace dilithium
