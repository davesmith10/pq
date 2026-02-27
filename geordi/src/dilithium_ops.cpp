#include "dilithium_ops.hpp"
#include <stdexcept>

namespace dilithium {

void keygen(const DilithiumParams& p,
            std::vector<uint8_t>& pk,
            std::vector<uint8_t>& sk)
{
    pk.resize(p.pk_bytes);
    sk.resize(p.sk_bytes);

    int rc = p.keypair(pk.data(), sk.data());
    if (rc != 0)
        throw std::runtime_error("Dilithium keygen failed (rc=" + std::to_string(rc) + ")");
}

void sign(const DilithiumParams& p,
          const std::vector<uint8_t>& sk,
          const std::vector<uint8_t>& msg,
          const uint8_t* ctx, size_t ctxlen,
          std::vector<uint8_t>& sig)
{
    if (sk.size() != p.sk_bytes)
        throw std::invalid_argument("Secret key size mismatch: expected " +
            std::to_string(p.sk_bytes) + " bytes, got " + std::to_string(sk.size()));

    sig.resize(p.sig_bytes);
    size_t siglen = 0;

    int rc = p.sign_sig(sig.data(), &siglen,
                        msg.data(), msg.size(),
                        ctx, ctxlen,
                        sk.data());
    if (rc != 0)
        throw std::runtime_error("Dilithium sign failed (rc=" + std::to_string(rc) + ")");

    sig.resize(siglen);
}

bool verify(const DilithiumParams& p,
            const std::vector<uint8_t>& pk,
            const std::vector<uint8_t>& msg,
            const uint8_t* ctx, size_t ctxlen,
            const std::vector<uint8_t>& sig)
{
    if (pk.size() != p.pk_bytes)
        throw std::invalid_argument("Public key size mismatch: expected " +
            std::to_string(p.pk_bytes) + " bytes, got " + std::to_string(pk.size()));

    int rc = p.verify_sig(sig.data(), sig.size(),
                          msg.data(), msg.size(),
                          ctx, ctxlen,
                          pk.data());
    return (rc == 0);
}

} // namespace dilithium
