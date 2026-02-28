#include "ec_sig.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <stdexcept>
#include <string>

namespace ec_sig {

bool is_classical_sig(const std::string& alg_name) {
    return alg_name == "Ed25519"    ||
           alg_name == "ECDSA P-256" ||
           alg_name == "ECDSA P-384" ||
           alg_name == "ECDSA P-521";
}

size_t sig_bytes(const std::string& alg_name) {
    if (alg_name == "Ed25519")     return 64;
    if (alg_name == "ECDSA P-256") return 64;   // P1363: 32+32
    if (alg_name == "ECDSA P-384") return 96;   // P1363: 48+48
    if (alg_name == "ECDSA P-521") return 132;  // P1363: 66+66
    throw std::invalid_argument("Unknown classical sig algorithm: " + alg_name);
}

// ── Ed25519 ──────────────────────────────────────────────────────────────────

static void ed25519_sign(const std::vector<uint8_t>& sk,
                          const std::vector<uint8_t>& msg,
                          std::vector<uint8_t>& sig_out)
{
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                   sk.data(), sk.size());
    if (!pkey) throw std::runtime_error("Ed25519 sign: load sk failed");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Ed25519 sign: EVP_MD_CTX_new failed");
    }

    // Ed25519 requires nullptr md (hashes internally) and one-shot signing
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Ed25519 sign: DigestSignInit failed");
    }

    sig_out.resize(64);
    size_t sig_len = 64;
    if (EVP_DigestSign(ctx, sig_out.data(), &sig_len,
                       msg.data(), msg.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Ed25519 sign: DigestSign failed");
    }
    sig_out.resize(sig_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

static bool ed25519_verify(const std::vector<uint8_t>& pk,
                            const std::vector<uint8_t>& msg,
                            const std::vector<uint8_t>& sig)
{
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                  pk.data(), pk.size());
    if (!pkey) throw std::runtime_error("Ed25519 verify: load pk failed");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Ed25519 verify: EVP_MD_CTX_new failed");
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Ed25519 verify: DigestVerifyInit failed");
    }

    int rc = EVP_DigestVerify(ctx, sig.data(), sig.size(),
                              msg.data(), msg.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return (rc == 1);
}

// ── ECDSA P-curves ───────────────────────────────────────────────────────────

struct ECDSAParams {
    const char* group_name;
    int         nid;
    size_t      scalar_bytes;      // each of r and s is this many bytes in P1363
    const EVP_MD* (*md_fn)();      // digest matching curve security level
};

static ECDSAParams ecdsa_params(const std::string& alg_name) {
    if (alg_name == "ECDSA P-256") return {"prime256v1", NID_X9_62_prime256v1, 32, EVP_sha256};
    if (alg_name == "ECDSA P-384") return {"secp384r1",  NID_secp384r1,        48, EVP_sha384};
    if (alg_name == "ECDSA P-521") return {"secp521r1",  NID_secp521r1,        66, EVP_sha512};
    throw std::invalid_argument("Unknown ECDSA algorithm: " + alg_name);
}

// Load EC public key from uncompressed point bytes
static EVP_PKEY* load_ec_pubkey_sig(const char* group_name,
                                     const uint8_t* pk, size_t pk_len)
{
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) return nullptr;
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, (void*)pk, pk_len);
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) return nullptr;

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY* pkey = nullptr;
    if (pctx) {
        EVP_PKEY_fromdata_init(pctx);
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
        EVP_PKEY_CTX_free(pctx);
    }
    OSSL_PARAM_free(params);
    return pkey;
}

// Load EC private key from big-endian scalar bytes
static EVP_PKEY* load_ec_privkey_sig(const char* group_name,
                                      const uint8_t* sk, size_t sk_len)
{
    BIGNUM* priv_bn = BN_bin2bn(sk, (int)sk_len, nullptr);
    if (!priv_bn) return nullptr;

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) { BN_free(priv_bn); return nullptr; }
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn);
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    BN_free(priv_bn);
    if (!params) return nullptr;

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY* pkey = nullptr;
    if (pctx) {
        EVP_PKEY_fromdata_init(pctx);
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params);
        EVP_PKEY_CTX_free(pctx);
    }
    OSSL_PARAM_free(params);
    return pkey;
}

// Convert DER-encoded ECDSA signature to IEEE P1363 format (raw r||s, zero-padded)
static std::vector<uint8_t> der_to_p1363(const uint8_t* der, size_t der_len,
                                          size_t scalar_bytes)
{
    const unsigned char* p = (const unsigned char*)der;
    ECDSA_SIG* dsig = d2i_ECDSA_SIG(nullptr, &p, (long)der_len);
    if (!dsig)
        throw std::runtime_error("der_to_p1363: d2i_ECDSA_SIG failed");

    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(dsig, &r, &s);

    std::vector<uint8_t> out(2 * scalar_bytes, 0);
    if (BN_bn2binpad(r, out.data(),                (int)scalar_bytes) < 0 ||
        BN_bn2binpad(s, out.data() + scalar_bytes, (int)scalar_bytes) < 0) {
        ECDSA_SIG_free(dsig);
        throw std::runtime_error("der_to_p1363: BN_bn2binpad failed");
    }
    ECDSA_SIG_free(dsig);
    return out;
}

// Convert IEEE P1363 format (raw r||s) to DER-encoded ECDSA signature
static std::vector<uint8_t> p1363_to_der(const uint8_t* p1363, size_t scalar_bytes)
{
    BIGNUM* r = BN_bin2bn(p1363,                scalar_bytes, nullptr);
    BIGNUM* s = BN_bin2bn(p1363 + scalar_bytes, scalar_bytes, nullptr);
    if (!r || !s) {
        BN_free(r);
        BN_free(s);
        throw std::runtime_error("p1363_to_der: BN_bin2bn failed");
    }

    ECDSA_SIG* dsig = ECDSA_SIG_new();
    if (!dsig) {
        BN_free(r);
        BN_free(s);
        throw std::runtime_error("p1363_to_der: ECDSA_SIG_new failed");
    }
    ECDSA_SIG_set0(dsig, r, s);  // transfers ownership of r and s

    unsigned char* der = nullptr;
    int der_len = i2d_ECDSA_SIG(dsig, &der);
    ECDSA_SIG_free(dsig);        // also frees r and s
    if (der_len <= 0)
        throw std::runtime_error("p1363_to_der: i2d_ECDSA_SIG failed");

    std::vector<uint8_t> out(der, der + der_len);
    OPENSSL_free(der);
    return out;
}

static void ecdsa_sign(const ECDSAParams& ecp,
                        const std::vector<uint8_t>& sk,
                        const std::vector<uint8_t>& msg,
                        std::vector<uint8_t>& sig_out)
{
    EVP_PKEY* pkey = load_ec_privkey_sig(ecp.group_name, sk.data(), sk.size());
    if (!pkey) throw std::runtime_error("ECDSA sign: load sk failed");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("ECDSA sign: EVP_MD_CTX_new failed");
    }

    if (EVP_DigestSignInit(ctx, nullptr, ecp.md_fn(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("ECDSA sign: DigestSignInit failed");
    }

    // Allocate buffer large enough for any DER-encoded ECDSA signature (P-521 ≤ 142 bytes)
    std::vector<uint8_t> der(256, 0);
    size_t der_len = der.size();
    if (EVP_DigestSign(ctx, der.data(), &der_len, msg.data(), msg.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("ECDSA sign: DigestSign failed");
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    // Convert DER → P1363
    sig_out = der_to_p1363(der.data(), der_len, ecp.scalar_bytes);
}

static bool ecdsa_verify(const ECDSAParams& ecp,
                          const std::vector<uint8_t>& pk,
                          const std::vector<uint8_t>& msg,
                          const std::vector<uint8_t>& sig)
{
    if (sig.size() != 2 * ecp.scalar_bytes)
        return false;

    // Convert P1363 → DER
    std::vector<uint8_t> der;
    try {
        der = p1363_to_der(sig.data(), ecp.scalar_bytes);
    } catch (...) {
        return false;
    }

    EVP_PKEY* pkey = load_ec_pubkey_sig(ecp.group_name, pk.data(), pk.size());
    if (!pkey) throw std::runtime_error("ECDSA verify: load pk failed");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("ECDSA verify: EVP_MD_CTX_new failed");
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, ecp.md_fn(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("ECDSA verify: DigestVerifyInit failed");
    }

    int rc = EVP_DigestVerify(ctx, der.data(), der.size(), msg.data(), msg.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return (rc == 1);
}

// ── Public API ────────────────────────────────────────────────────────────────

void sign(const std::string& alg_name,
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          std::vector<uint8_t>& sig_out)
{
    if (alg_name == "Ed25519") {
        ed25519_sign(sk, msg, sig_out);
    } else {
        ecdsa_sign(ecdsa_params(alg_name), sk, msg, sig_out);
    }
}

bool verify(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const std::vector<uint8_t>& sig)
{
    if (alg_name == "Ed25519") {
        return ed25519_verify(pk, msg, sig);
    } else {
        return ecdsa_verify(ecdsa_params(alg_name), pk, msg, sig);
    }
}

} // namespace ec_sig
