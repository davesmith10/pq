#include "dilithium_sig.hpp"
#include "dilithium_api.hpp"
#include <stdexcept>

namespace dilithium_sig {

bool is_pq_sig(const std::string& alg_name) {
    return alg_name == "Dilithium2" ||
           alg_name == "Dilithium3" ||
           alg_name == "Dilithium5";
}

int mode_from_alg(const std::string& alg_name) {
    if (alg_name == "Dilithium2") return 2;
    if (alg_name == "Dilithium3") return 3;
    if (alg_name == "Dilithium5") return 5;
    throw std::invalid_argument("Unknown Dilithium algorithm: " + alg_name);
}

size_t sig_bytes_for_mode(int mode) {
    switch (mode) {
        case 2: return DILITHIUM2_SIG_BYTES;
        case 3: return DILITHIUM3_SIG_BYTES;
        case 5: return DILITHIUM5_SIG_BYTES;
        default: throw std::invalid_argument("Invalid Dilithium mode: " + std::to_string(mode));
    }
}

void sign(int mode,
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          std::vector<uint8_t>& sig_out)
{
    size_t max_sig = sig_bytes_for_mode(mode);
    sig_out.resize(max_sig);
    size_t siglen = 0;
    int rc = 0;

    switch (mode) {
        case 2:
            rc = pqcrystals_dilithium2_ref_signature(
                sig_out.data(), &siglen,
                msg.data(), msg.size(),
                nullptr, 0,
                sk.data());
            break;
        case 3:
            rc = pqcrystals_dilithium3_ref_signature(
                sig_out.data(), &siglen,
                msg.data(), msg.size(),
                nullptr, 0,
                sk.data());
            break;
        case 5:
            rc = pqcrystals_dilithium5_ref_signature(
                sig_out.data(), &siglen,
                msg.data(), msg.size(),
                nullptr, 0,
                sk.data());
            break;
        default:
            throw std::invalid_argument("Invalid Dilithium mode");
    }

    if (rc != 0)
        throw std::runtime_error("Dilithium signature failed (rc=" + std::to_string(rc) + ")");
    sig_out.resize(siglen);
}

bool verify(int mode,
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const std::vector<uint8_t>& sig)
{
    int rc = 0;

    switch (mode) {
        case 2:
            rc = pqcrystals_dilithium2_ref_verify(
                sig.data(), sig.size(),
                msg.data(), msg.size(),
                nullptr, 0,
                pk.data());
            break;
        case 3:
            rc = pqcrystals_dilithium3_ref_verify(
                sig.data(), sig.size(),
                msg.data(), msg.size(),
                nullptr, 0,
                pk.data());
            break;
        case 5:
            rc = pqcrystals_dilithium5_ref_verify(
                sig.data(), sig.size(),
                msg.data(), msg.size(),
                nullptr, 0,
                pk.data());
            break;
        default:
            throw std::invalid_argument("Invalid Dilithium mode");
    }

    return (rc == 0);
}

} // namespace dilithium_sig
