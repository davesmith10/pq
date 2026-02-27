#include "kyber_ops.hpp"
#include "kyber_api.hpp"
#include <stdexcept>

namespace kyber {

void keygen(int level, std::vector<uint8_t>& pk, std::vector<uint8_t>& sk) {
    auto sz = kyber_sizes(level);
    pk.resize(sz.pk_bytes);
    sk.resize(sz.sk_bytes);

    int rc = 0;
    switch (level) {
        case 512:  rc = pqcrystals_kyber512_ref_keypair(pk.data(), sk.data()); break;
        case 768:  rc = pqcrystals_kyber768_ref_keypair(pk.data(), sk.data()); break;
        case 1024: rc = pqcrystals_kyber1024_ref_keypair(pk.data(), sk.data()); break;
        default:   throw std::logic_error("Invalid Kyber level in keygen");
    }
    if (rc != 0)
        throw std::runtime_error("Kyber keygen failed (rc=" + std::to_string(rc) + ")");
}

} // namespace kyber
