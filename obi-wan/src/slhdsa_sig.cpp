#include "slhdsa_sig.hpp"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdexcept>
#include <string>

namespace slhdsa_sig {

bool is_slhdsa_sig(const std::string& alg_name) {
    return alg_name.size() >= 7 && alg_name.substr(0, 7) == "SLH-DSA";
}

size_t sig_bytes(const std::string& alg_name) {
    if (alg_name == "SLH-DSA-SHA2-128f")  return 17088;
    if (alg_name == "SLH-DSA-SHA2-192f")  return 35664;
    if (alg_name == "SLH-DSA-SHA2-256f")  return 49856;
    if (alg_name == "SLH-DSA-SHAKE-192f") return 35664;
    if (alg_name == "SLH-DSA-SHAKE-256f") return 49856;
    throw std::invalid_argument("Unknown SLH-DSA algorithm: " + alg_name);
}

void sign(const std::string& alg_name,
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          std::vector<uint8_t>& sig_out)
{
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string("priv", (void*)sk.data(), sk.size());
    params[1] = OSSL_PARAM_construct_end();

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, alg_name.c_str(), nullptr);
    if (!pctx)
        throw std::runtime_error("SLH-DSA sign: EVP_PKEY_CTX_new_from_name failed for " + alg_name);

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("SLH-DSA sign: fromdata_init failed");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("SLH-DSA sign: fromdata failed");
    }
    EVP_PKEY_CTX_free(pctx);

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (!mctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("SLH-DSA sign: EVP_MD_CTX_new failed");
    }

    if (EVP_DigestSignInit_ex(mctx, nullptr, nullptr, nullptr, nullptr, pkey, nullptr) <= 0) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("SLH-DSA sign: DigestSignInit_ex failed");
    }

    // Two-call: query size then fill
    size_t sig_len = 0;
    if (EVP_DigestSign(mctx, nullptr, &sig_len, msg.data(), msg.size()) <= 0) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("SLH-DSA sign: size query failed");
    }

    sig_out.resize(sig_len);
    if (EVP_DigestSign(mctx, sig_out.data(), &sig_len, msg.data(), msg.size()) <= 0) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("SLH-DSA sign: DigestSign failed");
    }
    sig_out.resize(sig_len);

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
}

bool verify(const std::string& alg_name,
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const std::vector<uint8_t>& sig)
{
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string("pub", (void*)pk.data(), pk.size());
    params[1] = OSSL_PARAM_construct_end();

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, alg_name.c_str(), nullptr);
    if (!pctx)
        throw std::runtime_error("SLH-DSA verify: EVP_PKEY_CTX_new_from_name failed for " + alg_name);

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("SLH-DSA verify: fromdata_init failed");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("SLH-DSA verify: fromdata failed");
    }
    EVP_PKEY_CTX_free(pctx);

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (!mctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("SLH-DSA verify: EVP_MD_CTX_new failed");
    }

    if (EVP_DigestVerifyInit_ex(mctx, nullptr, nullptr, nullptr, nullptr, pkey, nullptr) <= 0) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("SLH-DSA verify: DigestVerifyInit_ex failed");
    }

    int rc = EVP_DigestVerify(mctx, sig.data(), sig.size(), msg.data(), msg.size());
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return (rc == 1);
}

} // namespace slhdsa_sig
