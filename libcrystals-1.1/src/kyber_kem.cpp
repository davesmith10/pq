#include "kyber_kem.hpp"
#include "kyber_api.hpp"
#include <string>
#include <stdexcept>

namespace kyber_kem {

int level_from_alg(const std::string& alg_name) {
    if (alg_name == "Kyber512")  return 512;
    if (alg_name == "Kyber768")  return 768;
    if (alg_name == "Kyber1024") return 1024;
    throw std::invalid_argument("Unknown Kyber alg_name: " + alg_name);
}

void encaps(int level,
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct_out,
            std::vector<uint8_t>& ss_out)
{
    auto sz = kyber_kem_sizes(level);
    if (pk.size() != sz.pk_bytes)
        throw std::invalid_argument("Kyber pk size mismatch");

    ct_out.resize(sz.ct_bytes);
    ss_out.resize(sz.ss_bytes);

    int rc = 0;
    switch (level) {
        case 512:  rc = pqcrystals_kyber512_ref_enc(ct_out.data(), ss_out.data(), pk.data());  break;
        case 768:  rc = pqcrystals_kyber768_ref_enc(ct_out.data(), ss_out.data(), pk.data());  break;
        case 1024: rc = pqcrystals_kyber1024_ref_enc(ct_out.data(), ss_out.data(), pk.data()); break;
        default:   throw std::logic_error("Invalid Kyber level");
    }
    if (rc != 0)
        throw std::runtime_error("Kyber encaps failed (rc=" + std::to_string(rc) + ")");
}

void decaps(int level,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out)
{
    auto sz = kyber_kem_sizes(level);
    if (sk.size() != sz.sk_bytes)
        throw std::invalid_argument("Kyber sk size mismatch");
    if (ct.size() != sz.ct_bytes)
        throw std::invalid_argument("Kyber ct size mismatch");

    ss_out.resize(sz.ss_bytes);

    int rc = 0;
    switch (level) {
        case 512:  rc = pqcrystals_kyber512_ref_dec(ss_out.data(), ct.data(), sk.data());  break;
        case 768:  rc = pqcrystals_kyber768_ref_dec(ss_out.data(), ct.data(), sk.data());  break;
        case 1024: rc = pqcrystals_kyber1024_ref_dec(ss_out.data(), ct.data(), sk.data()); break;
        default:   throw std::logic_error("Invalid Kyber level");
    }
    if (rc != 0)
        throw std::runtime_error("Kyber decaps failed (rc=" + std::to_string(rc) + ")");
}

} // namespace kyber_kem
