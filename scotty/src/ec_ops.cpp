#include "ec_ops.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <stdexcept>
#include <string>

namespace ec {

// ── X25519 / Ed25519 ──────────────────────────────────────────────────────────
// Both use 32-byte raw key representation.

static KeyPair keygen_raw_curve(int nid) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(nid, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen_init failed");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }
    EVP_PKEY_CTX_free(ctx);

    KeyPair kp;
    kp.pk.resize(32);
    kp.sk.resize(32);

    size_t pk_len = 32, sk_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, kp.pk.data(), &pk_len) <= 0 ||
        EVP_PKEY_get_raw_private_key(pkey, kp.sk.data(), &sk_len) <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to extract raw keys");
    }
    kp.pk.resize(pk_len);
    kp.sk.resize(sk_len);

    EVP_PKEY_free(pkey);
    return kp;
}

// ── NIST EC curves (P-256, P-384, P-521) ─────────────────────────────────────
// pk: uncompressed SEC1 point (04 || x || y)
// sk: big-endian scalar padded to curve order size

static KeyPair keygen_ec_curve(int curve_nid, size_t pk_size, size_t sk_size) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id (EC) failed");

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen_init failed");
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen (EC) failed");
    }
    EVP_PKEY_CTX_free(ctx);

    // Public key: uncompressed point via OSSL_PKEY_PARAM_PUB_KEY
    KeyPair kp;
    kp.pk.resize(pk_size);
    size_t pk_len = pk_size;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        kp.pk.data(), pk_size, &pk_len) <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to get EC public key");
    }
    kp.pk.resize(pk_len);

    // Private key: BIGNUM, zero-padded to sk_size bytes
    BIGNUM* priv_bn = nullptr;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to get EC private key");
    }
    EVP_PKEY_free(pkey);

    int priv_len = BN_num_bytes(priv_bn);
    if ((size_t)priv_len > sk_size) {
        BN_free(priv_bn);
        throw std::runtime_error("EC private key scalar too large");
    }
    kp.sk.assign(sk_size, 0);
    BN_bn2bin(priv_bn, kp.sk.data() + (sk_size - (size_t)priv_len));
    BN_free(priv_bn);

    return kp;
}

// ── Public API ────────────────────────────────────────────────────────────────

KeyPair keygen(Algorithm alg) {
    switch (alg) {
        case Algorithm::X25519:  return keygen_raw_curve(EVP_PKEY_X25519);
        case Algorithm::Ed25519: return keygen_raw_curve(EVP_PKEY_ED25519);
        case Algorithm::P256:    return keygen_ec_curve(NID_X9_62_prime256v1, 65, 32);
        case Algorithm::P384:    return keygen_ec_curve(NID_secp384r1,        97, 48);
        case Algorithm::P521:    return keygen_ec_curve(NID_secp521r1,       133, 66);
        default:
            throw std::invalid_argument("Unknown EC algorithm");
    }
}

} // namespace ec
