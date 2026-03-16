#include "mceliece_ops.hpp"
#include <stdexcept>

extern "C" {
#include <mceliece.h>
}

namespace mcs {

McElieceKeys keygen_mceliece(const std::string& param_set) {
    McElieceKeys keys;

    if (param_set == "mceliece348864f") {
        keys.pk.resize(mceliece348864f_PUBLICKEYBYTES);
        keys.sk.resize(mceliece348864f_SECRETKEYBYTES);
        mceliece348864f_keypair(keys.pk.data(), keys.sk.data());
    } else if (param_set == "mceliece460896f") {
        keys.pk.resize(mceliece460896f_PUBLICKEYBYTES);
        keys.sk.resize(mceliece460896f_SECRETKEYBYTES);
        mceliece460896f_keypair(keys.pk.data(), keys.sk.data());
    } else if (param_set == "mceliece6688128f") {
        keys.pk.resize(mceliece6688128f_PUBLICKEYBYTES);
        keys.sk.resize(mceliece6688128f_SECRETKEYBYTES);
        mceliece6688128f_keypair(keys.pk.data(), keys.sk.data());
    } else if (param_set == "mceliece6960119f") {
        keys.pk.resize(mceliece6960119f_PUBLICKEYBYTES);
        keys.sk.resize(mceliece6960119f_SECRETKEYBYTES);
        mceliece6960119f_keypair(keys.pk.data(), keys.sk.data());
    } else if (param_set == "mceliece8192128f") {
        keys.pk.resize(mceliece8192128f_PUBLICKEYBYTES);
        keys.sk.resize(mceliece8192128f_SECRETKEYBYTES);
        mceliece8192128f_keypair(keys.pk.data(), keys.sk.data());
    } else {
        throw std::invalid_argument("Unknown McEliece param set: " + param_set);
    }

    return keys;
}

} // namespace mcs
