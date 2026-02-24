#include "kyber_ops.hpp"
#include <stdexcept>

extern "C" {
#include "fips202.h"
}

namespace kyber {

void keygen(const KyberParams& p,
            std::vector<uint8_t>& pk,
            std::vector<uint8_t>& sk)
{
    pk.resize(p.pk_bytes);
    sk.resize(p.sk_bytes);

    int rc = 0;
    if (!p.avx2) {
        switch (p.level) {
            case 512:  rc = pqcrystals_kyber512_ref_keypair(pk.data(), sk.data()); break;
            case 768:  rc = pqcrystals_kyber768_ref_keypair(pk.data(), sk.data()); break;
            case 1024: rc = pqcrystals_kyber1024_ref_keypair(pk.data(), sk.data()); break;
            default: throw std::logic_error("Invalid level in keygen");
        }
    } else {
        switch (p.level) {
            case 512:  rc = pqcrystals_kyber512_avx2_keypair(pk.data(), sk.data()); break;
            case 768:  rc = pqcrystals_kyber768_avx2_keypair(pk.data(), sk.data()); break;
            case 1024: rc = pqcrystals_kyber1024_avx2_keypair(pk.data(), sk.data()); break;
            default: throw std::logic_error("Invalid level in keygen");
        }
    }
    if (rc != 0)
        throw std::runtime_error("Kyber keygen failed (rc=" + std::to_string(rc) + ")");
}

void encaps(const KyberParams& p,
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss)
{
    if (pk.size() != p.pk_bytes)
        throw std::invalid_argument("Public key size mismatch: expected " +
            std::to_string(p.pk_bytes) + " bytes, got " + std::to_string(pk.size()));

    ct.resize(p.ct_bytes);
    ss.resize(p.ss_bytes);

    int rc = 0;
    if (!p.avx2) {
        switch (p.level) {
            case 512:  rc = pqcrystals_kyber512_ref_enc(ct.data(), ss.data(), pk.data()); break;
            case 768:  rc = pqcrystals_kyber768_ref_enc(ct.data(), ss.data(), pk.data()); break;
            case 1024: rc = pqcrystals_kyber1024_ref_enc(ct.data(), ss.data(), pk.data()); break;
            default: throw std::logic_error("Invalid level in encaps");
        }
    } else {
        switch (p.level) {
            case 512:  rc = pqcrystals_kyber512_avx2_enc(ct.data(), ss.data(), pk.data()); break;
            case 768:  rc = pqcrystals_kyber768_avx2_enc(ct.data(), ss.data(), pk.data()); break;
            case 1024: rc = pqcrystals_kyber1024_avx2_enc(ct.data(), ss.data(), pk.data()); break;
            default: throw std::logic_error("Invalid level in encaps");
        }
    }
    if (rc != 0)
        throw std::runtime_error("Kyber encaps failed (rc=" + std::to_string(rc) + ")");
}

void decaps(const KyberParams& p,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss)
{
    if (sk.size() != p.sk_bytes)
        throw std::invalid_argument("Secret key size mismatch: expected " +
            std::to_string(p.sk_bytes) + " bytes, got " + std::to_string(sk.size()));
    if (ct.size() != p.ct_bytes)
        throw std::invalid_argument("Ciphertext size mismatch: expected " +
            std::to_string(p.ct_bytes) + " bytes, got " + std::to_string(ct.size()));

    ss.resize(p.ss_bytes);

    int rc = 0;
    if (!p.avx2) {
        switch (p.level) {
            case 512:  rc = pqcrystals_kyber512_ref_dec(ss.data(), ct.data(), sk.data()); break;
            case 768:  rc = pqcrystals_kyber768_ref_dec(ss.data(), ct.data(), sk.data()); break;
            case 1024: rc = pqcrystals_kyber1024_ref_dec(ss.data(), ct.data(), sk.data()); break;
            default: throw std::logic_error("Invalid level in decaps");
        }
    } else {
        switch (p.level) {
            case 512:  rc = pqcrystals_kyber512_avx2_dec(ss.data(), ct.data(), sk.data()); break;
            case 768:  rc = pqcrystals_kyber768_avx2_dec(ss.data(), ct.data(), sk.data()); break;
            case 1024: rc = pqcrystals_kyber1024_avx2_dec(ss.data(), ct.data(), sk.data()); break;
            default: throw std::logic_error("Invalid level in decaps");
        }
    }
    if (rc != 0)
        throw std::runtime_error("Kyber decaps failed (rc=" + std::to_string(rc) + ")");
}

// Expand 32-byte user seed → 64-byte coins for keygen via SHAKE256
static void expand_seed(const uint8_t seed[32], uint8_t out[64]) {
    shake256(out, 64, seed, 32);
}

void keygen_derand(const KyberParams& p,
                   const uint8_t seed[32],
                   std::vector<uint8_t>& pk,
                   std::vector<uint8_t>& sk)
{
    pk.resize(p.pk_bytes);
    sk.resize(p.sk_bytes);

    uint8_t coins[64];
    expand_seed(seed, coins);

    int rc = 0;
    if (!p.avx2) {
        switch (p.level) {
            case 512:  rc = pqcrystals_kyber512_ref_keypair_derand(pk.data(), sk.data(), coins); break;
            case 768:  rc = pqcrystals_kyber768_ref_keypair_derand(pk.data(), sk.data(), coins); break;
            case 1024: rc = pqcrystals_kyber1024_ref_keypair_derand(pk.data(), sk.data(), coins); break;
            default: throw std::logic_error("Invalid level in keygen_derand");
        }
    } else {
        switch (p.level) {
            case 512:  rc = pqcrystals_kyber512_avx2_keypair_derand(pk.data(), sk.data(), coins); break;
            case 768:  rc = pqcrystals_kyber768_avx2_keypair_derand(pk.data(), sk.data(), coins); break;
            case 1024: rc = pqcrystals_kyber1024_avx2_keypair_derand(pk.data(), sk.data(), coins); break;
            default: throw std::logic_error("Invalid level in keygen_derand");
        }
    }
    if (rc != 0)
        throw std::runtime_error("Kyber keygen_derand failed (rc=" + std::to_string(rc) + ")");
}

void encaps_derand(const KyberParams& p,
                   const std::vector<uint8_t>& pk,
                   const uint8_t seed[32],
                   std::vector<uint8_t>& ct,
                   std::vector<uint8_t>& ss)
{
    if (pk.size() != p.pk_bytes)
        throw std::invalid_argument("Public key size mismatch: expected " +
            std::to_string(p.pk_bytes) + " bytes, got " + std::to_string(pk.size()));

    ct.resize(p.ct_bytes);
    ss.resize(p.ss_bytes);

    int rc = 0;
    if (!p.avx2) {
        switch (p.level) {
            case 512:  rc = pqcrystals_kyber512_ref_enc_derand(ct.data(), ss.data(), pk.data(), seed); break;
            case 768:  rc = pqcrystals_kyber768_ref_enc_derand(ct.data(), ss.data(), pk.data(), seed); break;
            case 1024: rc = pqcrystals_kyber1024_ref_enc_derand(ct.data(), ss.data(), pk.data(), seed); break;
            default: throw std::logic_error("Invalid level in encaps_derand");
        }
    } else {
        switch (p.level) {
            case 512:  rc = pqcrystals_kyber512_avx2_enc_derand(ct.data(), ss.data(), pk.data(), seed); break;
            case 768:  rc = pqcrystals_kyber768_avx2_enc_derand(ct.data(), ss.data(), pk.data(), seed); break;
            case 1024: rc = pqcrystals_kyber1024_avx2_enc_derand(ct.data(), ss.data(), pk.data(), seed); break;
            default: throw std::logic_error("Invalid level in encaps_derand");
        }
    }
    if (rc != 0)
        throw std::runtime_error("Kyber encaps_derand failed (rc=" + std::to_string(rc) + ")");
}

} // namespace kyber
