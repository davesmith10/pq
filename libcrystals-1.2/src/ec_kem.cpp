#include "ec_kem.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <stdexcept>
#include <string>

namespace ec_kem {

bool is_classical_kem(const std::string& alg_name) {
    return alg_name == "X25519" || alg_name == "P-256" ||
           alg_name == "P-384"  || alg_name == "P-521";
}

// ── X25519 ────────────────────────────────────────────────────────────────────

static void x25519_encaps(const std::vector<uint8_t>& pk,
                           std::vector<uint8_t>& ct_out,
                           std::vector<uint8_t>& ss_out)
{
    // Generate ephemeral X25519 keypair
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!kctx) throw std::runtime_error("X25519: EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        throw std::runtime_error("X25519: keygen_init failed");
    }
    EVP_PKEY* eph = nullptr;
    if (EVP_PKEY_keygen(kctx, &eph) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        throw std::runtime_error("X25519: keygen failed");
    }
    EVP_PKEY_CTX_free(kctx);

    // CT = ephemeral public key bytes
    ct_out.resize(32);
    size_t ct_len = 32;
    if (EVP_PKEY_get_raw_public_key(eph, ct_out.data(), &ct_len) <= 0) {
        EVP_PKEY_free(eph);
        throw std::runtime_error("X25519: get_raw_public_key failed");
    }
    ct_out.resize(ct_len);

    // Load recipient pk
    EVP_PKEY* rec_pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                     pk.data(), pk.size());
    if (!rec_pk) {
        EVP_PKEY_free(eph);
        throw std::runtime_error("X25519: load recipient pk failed");
    }

    // ECDH derive
    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(eph, nullptr);
    EVP_PKEY_free(eph);
    if (!dctx) {
        EVP_PKEY_free(rec_pk);
        throw std::runtime_error("X25519: EVP_PKEY_CTX_new (derive) failed");
    }
    if (EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, rec_pk) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(rec_pk);
        throw std::runtime_error("X25519: derive init/set_peer failed");
    }
    EVP_PKEY_free(rec_pk);

    size_t ss_len = 32;
    ss_out.resize(32);
    if (EVP_PKEY_derive(dctx, ss_out.data(), &ss_len) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        throw std::runtime_error("X25519: EVP_PKEY_derive failed");
    }
    EVP_PKEY_CTX_free(dctx);
    ss_out.resize(ss_len);
}

static void x25519_decaps(const std::vector<uint8_t>& sk,
                           const std::vector<uint8_t>& ct,
                           std::vector<uint8_t>& ss_out)
{
    // Load recipient sk
    EVP_PKEY* rec_sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                      sk.data(), sk.size());
    if (!rec_sk) throw std::runtime_error("X25519: load sk failed");

    // Load CT as ephemeral pk
    EVP_PKEY* eph_pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                     ct.data(), ct.size());
    if (!eph_pk) {
        EVP_PKEY_free(rec_sk);
        throw std::runtime_error("X25519: load ephemeral pk (CT) failed");
    }

    // ECDH derive
    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(rec_sk, nullptr);
    EVP_PKEY_free(rec_sk);
    if (!dctx) {
        EVP_PKEY_free(eph_pk);
        throw std::runtime_error("X25519: EVP_PKEY_CTX_new (derive) failed");
    }
    if (EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, eph_pk) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(eph_pk);
        throw std::runtime_error("X25519: derive init/set_peer failed");
    }
    EVP_PKEY_free(eph_pk);

    size_t ss_len = 32;
    ss_out.resize(32);
    if (EVP_PKEY_derive(dctx, ss_out.data(), &ss_len) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        throw std::runtime_error("X25519: EVP_PKEY_derive failed");
    }
    EVP_PKEY_CTX_free(dctx);
    ss_out.resize(ss_len);
}

// ── NIST P-curves ─────────────────────────────────────────────────────────────

struct ECParams {
    const char* group_name;  // OpenSSL group name string
    int         nid;          // NID for keygen
    size_t      pk_bytes;    // uncompressed point size
    size_t      sk_bytes;    // private scalar size
    size_t      ss_bytes;    // shared secret = x-coordinate size
};

static ECParams ec_params(const std::string& alg_name) {
    if (alg_name == "P-256") return {"prime256v1", NID_X9_62_prime256v1, 65, 32, 32};
    if (alg_name == "P-384") return {"secp384r1",  NID_secp384r1,        97, 48, 48};
    if (alg_name == "P-521") return {"secp521r1",  NID_secp521r1,       133, 66, 66};
    throw std::invalid_argument("Unknown EC KEM algorithm: " + alg_name);
}

// Load EC public key from uncompressed point bytes
static EVP_PKEY* load_ec_pubkey(const char* group_name, const uint8_t* pk, size_t pk_len) {
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) return nullptr;
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                    group_name, 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                     (void*)pk, pk_len);
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) return nullptr;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY* pkey = nullptr;
    if (ctx) {
        EVP_PKEY_fromdata_init(ctx);
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
        EVP_PKEY_CTX_free(ctx);
    }
    OSSL_PARAM_free(params);
    return pkey;
}

// Load EC private key from big-endian scalar bytes
static EVP_PKEY* load_ec_privkey(const char* group_name, const uint8_t* sk, size_t sk_len) {
    BIGNUM* priv_bn = BN_bin2bn(sk, (int)sk_len, nullptr);
    if (!priv_bn) return nullptr;

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) { BN_free(priv_bn); return nullptr; }
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                    group_name, 0);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn);
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    BN_free(priv_bn);
    if (!params) return nullptr;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY* pkey = nullptr;
    if (ctx) {
        EVP_PKEY_fromdata_init(ctx);
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
        EVP_PKEY_CTX_free(ctx);
    }
    OSSL_PARAM_free(params);
    return pkey;
}

static void p_curve_encaps(const ECParams& ecp,
                            const std::vector<uint8_t>& pk,
                            std::vector<uint8_t>& ct_out,
                            std::vector<uint8_t>& ss_out)
{
    // Generate ephemeral EC keypair
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!kctx) throw std::runtime_error("EC encaps: EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, ecp.nid) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        throw std::runtime_error("EC encaps: keygen init failed");
    }
    EVP_PKEY* eph = nullptr;
    if (EVP_PKEY_keygen(kctx, &eph) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        throw std::runtime_error("EC encaps: keygen failed");
    }
    EVP_PKEY_CTX_free(kctx);

    // CT = ephemeral public key (uncompressed point)
    ct_out.resize(ecp.pk_bytes);
    size_t ct_len = ecp.pk_bytes;
    if (EVP_PKEY_get_octet_string_param(eph, OSSL_PKEY_PARAM_PUB_KEY,
                                         ct_out.data(), ecp.pk_bytes, &ct_len) <= 0) {
        EVP_PKEY_free(eph);
        throw std::runtime_error("EC encaps: get ephemeral pk failed");
    }
    ct_out.resize(ct_len);

    // Load recipient public key
    EVP_PKEY* rec_pk = load_ec_pubkey(ecp.group_name, pk.data(), pk.size());
    if (!rec_pk) {
        EVP_PKEY_free(eph);
        throw std::runtime_error("EC encaps: load recipient pk failed");
    }

    // ECDH derive
    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(eph, nullptr);
    EVP_PKEY_free(eph);
    if (!dctx) {
        EVP_PKEY_free(rec_pk);
        throw std::runtime_error("EC encaps: EVP_PKEY_CTX_new failed");
    }
    if (EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, rec_pk) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(rec_pk);
        throw std::runtime_error("EC encaps: derive init/set_peer failed");
    }
    EVP_PKEY_free(rec_pk);

    size_t ss_len = ecp.ss_bytes;
    ss_out.resize(ecp.ss_bytes);
    if (EVP_PKEY_derive(dctx, ss_out.data(), &ss_len) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        throw std::runtime_error("EC encaps: EVP_PKEY_derive failed");
    }
    EVP_PKEY_CTX_free(dctx);
    ss_out.resize(ss_len);
}

static void p_curve_decaps(const ECParams& ecp,
                            const std::vector<uint8_t>& sk,
                            const std::vector<uint8_t>& ct,
                            std::vector<uint8_t>& ss_out)
{
    // Load recipient private key
    EVP_PKEY* rec_sk = load_ec_privkey(ecp.group_name, sk.data(), sk.size());
    if (!rec_sk) throw std::runtime_error("EC decaps: load sk failed");

    // Load ephemeral public key from CT
    EVP_PKEY* eph_pk = load_ec_pubkey(ecp.group_name, ct.data(), ct.size());
    if (!eph_pk) {
        EVP_PKEY_free(rec_sk);
        throw std::runtime_error("EC decaps: load CT (ephemeral pk) failed");
    }

    // ECDH derive
    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(rec_sk, nullptr);
    EVP_PKEY_free(rec_sk);
    if (!dctx) {
        EVP_PKEY_free(eph_pk);
        throw std::runtime_error("EC decaps: EVP_PKEY_CTX_new failed");
    }
    if (EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, eph_pk) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(eph_pk);
        throw std::runtime_error("EC decaps: derive init/set_peer failed");
    }
    EVP_PKEY_free(eph_pk);

    size_t ss_len = ecp.ss_bytes;
    ss_out.resize(ecp.ss_bytes);
    if (EVP_PKEY_derive(dctx, ss_out.data(), &ss_len) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        throw std::runtime_error("EC decaps: EVP_PKEY_derive failed");
    }
    EVP_PKEY_CTX_free(dctx);
    ss_out.resize(ss_len);
}

// ── Public API ────────────────────────────────────────────────────────────────

void encaps(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct_out,
            std::vector<uint8_t>& ss_out)
{
    if (alg_name == "X25519") {
        x25519_encaps(pk, ct_out, ss_out);
    } else {
        p_curve_encaps(ec_params(alg_name), pk, ct_out, ss_out);
    }
}

void decaps(const std::string& alg_name,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out)
{
    if (alg_name == "X25519") {
        x25519_decaps(sk, ct, ss_out);
    } else {
        p_curve_decaps(ec_params(alg_name), sk, ct, ss_out);
    }
}

} // namespace ec_kem
