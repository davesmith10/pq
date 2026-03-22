#include "slhdsa_ops.hpp"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <stdexcept>

namespace mcs {

SlhDsaKeys keygen_slhdsa(const std::string& alg_name) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, alg_name.c_str(), nullptr);
    if (!ctx)
        throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed for " + alg_name);

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen_init failed for " + alg_name);
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen failed for " + alg_name);
    }
    EVP_PKEY_CTX_free(ctx);

    SlhDsaKeys keys;

    // Get public key size then extract
    size_t pk_len = 0;
    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pk_len);
    if (pk_len == 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("SLH-DSA: failed to query public key size");
    }
    keys.pk.resize(pk_len);
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        keys.pk.data(), pk_len, &pk_len) <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("SLH-DSA: failed to extract public key");
    }

    // Get private key size then extract
    size_t sk_len = 0;
    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, nullptr, 0, &sk_len);
    if (sk_len == 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("SLH-DSA: failed to query private key size");
    }
    keys.sk.resize(sk_len);
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                        keys.sk.data(), sk_len, &sk_len) <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("SLH-DSA: failed to extract private key");
    }

    EVP_PKEY_free(pkey);
    return keys;
}

} // namespace mcs
