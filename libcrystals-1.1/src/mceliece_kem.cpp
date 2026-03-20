#include "mceliece_kem.hpp"
#include <stdexcept>

extern "C" {
#include <mceliece.h>
}

namespace mceliece_kem {

void encaps(const std::string& param_set,
            const std::vector<uint8_t>& pk,
            std::vector<uint8_t>& ct_out,
            std::vector<uint8_t>& ss_out)
{
    if (param_set == "mceliece348864f") {
        if (pk.size() != mceliece348864f_PUBLICKEYBYTES)
            throw std::invalid_argument("mceliece348864f pk size mismatch");
        ct_out.resize(mceliece348864f_CIPHERTEXTBYTES);
        ss_out.resize(mceliece348864f_BYTES);
        mceliece348864f_enc(ct_out.data(), ss_out.data(), pk.data());
    } else if (param_set == "mceliece460896f") {
        if (pk.size() != mceliece460896f_PUBLICKEYBYTES)
            throw std::invalid_argument("mceliece460896f pk size mismatch");
        ct_out.resize(mceliece460896f_CIPHERTEXTBYTES);
        ss_out.resize(mceliece460896f_BYTES);
        mceliece460896f_enc(ct_out.data(), ss_out.data(), pk.data());
    } else if (param_set == "mceliece6688128f") {
        if (pk.size() != mceliece6688128f_PUBLICKEYBYTES)
            throw std::invalid_argument("mceliece6688128f pk size mismatch");
        ct_out.resize(mceliece6688128f_CIPHERTEXTBYTES);
        ss_out.resize(mceliece6688128f_BYTES);
        mceliece6688128f_enc(ct_out.data(), ss_out.data(), pk.data());
    } else if (param_set == "mceliece6960119f") {
        if (pk.size() != mceliece6960119f_PUBLICKEYBYTES)
            throw std::invalid_argument("mceliece6960119f pk size mismatch");
        ct_out.resize(mceliece6960119f_CIPHERTEXTBYTES);
        ss_out.resize(mceliece6960119f_BYTES);
        mceliece6960119f_enc(ct_out.data(), ss_out.data(), pk.data());
    } else if (param_set == "mceliece8192128f") {
        if (pk.size() != mceliece8192128f_PUBLICKEYBYTES)
            throw std::invalid_argument("mceliece8192128f pk size mismatch");
        ct_out.resize(mceliece8192128f_CIPHERTEXTBYTES);
        ss_out.resize(mceliece8192128f_BYTES);
        mceliece8192128f_enc(ct_out.data(), ss_out.data(), pk.data());
    } else {
        throw std::invalid_argument("Unknown McEliece param set: " + param_set);
    }
}

void decaps(const std::string& param_set,
            const std::vector<uint8_t>& sk,
            const std::vector<uint8_t>& ct,
            std::vector<uint8_t>& ss_out)
{
    int rc = 0;
    if (param_set == "mceliece348864f") {
        if (sk.size() != mceliece348864f_SECRETKEYBYTES)
            throw std::invalid_argument("mceliece348864f sk size mismatch");
        if (ct.size() != mceliece348864f_CIPHERTEXTBYTES)
            throw std::invalid_argument("mceliece348864f ct size mismatch");
        ss_out.resize(mceliece348864f_BYTES);
        rc = mceliece348864f_dec(ss_out.data(), ct.data(), sk.data());
    } else if (param_set == "mceliece460896f") {
        if (sk.size() != mceliece460896f_SECRETKEYBYTES)
            throw std::invalid_argument("mceliece460896f sk size mismatch");
        if (ct.size() != mceliece460896f_CIPHERTEXTBYTES)
            throw std::invalid_argument("mceliece460896f ct size mismatch");
        ss_out.resize(mceliece460896f_BYTES);
        rc = mceliece460896f_dec(ss_out.data(), ct.data(), sk.data());
    } else if (param_set == "mceliece6688128f") {
        if (sk.size() != mceliece6688128f_SECRETKEYBYTES)
            throw std::invalid_argument("mceliece6688128f sk size mismatch");
        if (ct.size() != mceliece6688128f_CIPHERTEXTBYTES)
            throw std::invalid_argument("mceliece6688128f ct size mismatch");
        ss_out.resize(mceliece6688128f_BYTES);
        rc = mceliece6688128f_dec(ss_out.data(), ct.data(), sk.data());
    } else if (param_set == "mceliece6960119f") {
        if (sk.size() != mceliece6960119f_SECRETKEYBYTES)
            throw std::invalid_argument("mceliece6960119f sk size mismatch");
        if (ct.size() != mceliece6960119f_CIPHERTEXTBYTES)
            throw std::invalid_argument("mceliece6960119f ct size mismatch");
        ss_out.resize(mceliece6960119f_BYTES);
        rc = mceliece6960119f_dec(ss_out.data(), ct.data(), sk.data());
    } else if (param_set == "mceliece8192128f") {
        if (sk.size() != mceliece8192128f_SECRETKEYBYTES)
            throw std::invalid_argument("mceliece8192128f sk size mismatch");
        if (ct.size() != mceliece8192128f_CIPHERTEXTBYTES)
            throw std::invalid_argument("mceliece8192128f ct size mismatch");
        ss_out.resize(mceliece8192128f_BYTES);
        rc = mceliece8192128f_dec(ss_out.data(), ct.data(), sk.data());
    } else {
        throw std::invalid_argument("Unknown McEliece param set: " + param_set);
    }
    if (rc != 0)
        throw std::runtime_error("McEliece decaps failed (rc=" + std::to_string(rc) + ")");
}

} // namespace mceliece_kem
