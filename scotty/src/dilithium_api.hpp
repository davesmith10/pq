#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <string>

// ── extern "C" declarations for all 12 Dilithium API functions ────────────────

extern "C" {

// ── ref ──────────────────────────────────────────────────────────────────────
int pqcrystals_dilithium2_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium2_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);
int pqcrystals_dilithium2_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);
int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int pqcrystals_dilithium5_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);
int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

// ── avx2 ─────────────────────────────────────────────────────────────────────
int pqcrystals_dilithium2_avx2_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium2_avx2_signature(uint8_t *sig, size_t *siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *sk);
int pqcrystals_dilithium2_avx2_verify(const uint8_t *sig, size_t siglen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *ctx, size_t ctxlen,
                                      const uint8_t *pk);

int pqcrystals_dilithium3_avx2_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium3_avx2_signature(uint8_t *sig, size_t *siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *sk);
int pqcrystals_dilithium3_avx2_verify(const uint8_t *sig, size_t siglen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *ctx, size_t ctxlen,
                                      const uint8_t *pk);

int pqcrystals_dilithium5_avx2_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_dilithium5_avx2_signature(uint8_t *sig, size_t *siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *sk);
int pqcrystals_dilithium5_avx2_verify(const uint8_t *sig, size_t siglen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *ctx, size_t ctxlen,
                                      const uint8_t *pk);

} // extern "C"

// ── DilithiumParams ───────────────────────────────────────────────────────────

struct DilithiumParams {
    int    mode;       // 2, 3, or 5
    bool   avx2;       // ref vs avx2
    size_t pk_bytes;   // 1312 / 1952 / 2592
    size_t sk_bytes;   // 2560 / 4032 / 4896
    size_t sig_bytes;  // 2420 / 3309 / 4627
    std::string label; // "DILITHIUM2", "DILITHIUM3", "DILITHIUM5"

    // function pointers
    int (*keypair)(uint8_t*, uint8_t*);
    int (*sign_sig)(uint8_t*, size_t*,
                   const uint8_t*, size_t,
                   const uint8_t*, size_t,
                   const uint8_t*);
    int (*verify_sig)(const uint8_t*, size_t,
                     const uint8_t*, size_t,
                     const uint8_t*, size_t,
                     const uint8_t*);
};

inline DilithiumParams make_params(int mode, bool use_avx2) {
    DilithiumParams p;
    p.mode = mode;
    p.avx2 = use_avx2;

    switch (mode) {
        case 2:
            p.pk_bytes  = 1312;
            p.sk_bytes  = 2560;
            p.sig_bytes = 2420;
            p.label     = "DILITHIUM2";
            if (!use_avx2) {
                p.keypair    = pqcrystals_dilithium2_ref_keypair;
                p.sign_sig   = pqcrystals_dilithium2_ref_signature;
                p.verify_sig = pqcrystals_dilithium2_ref_verify;
            } else {
                p.keypair    = pqcrystals_dilithium2_avx2_keypair;
                p.sign_sig   = pqcrystals_dilithium2_avx2_signature;
                p.verify_sig = pqcrystals_dilithium2_avx2_verify;
            }
            break;
        case 3:
            p.pk_bytes  = 1952;
            p.sk_bytes  = 4032;
            p.sig_bytes = 3309;
            p.label     = "DILITHIUM3";
            if (!use_avx2) {
                p.keypair    = pqcrystals_dilithium3_ref_keypair;
                p.sign_sig   = pqcrystals_dilithium3_ref_signature;
                p.verify_sig = pqcrystals_dilithium3_ref_verify;
            } else {
                p.keypair    = pqcrystals_dilithium3_avx2_keypair;
                p.sign_sig   = pqcrystals_dilithium3_avx2_signature;
                p.verify_sig = pqcrystals_dilithium3_avx2_verify;
            }
            break;
        case 5:
            p.pk_bytes  = 2592;
            p.sk_bytes  = 4896;
            p.sig_bytes = 4627;
            p.label     = "DILITHIUM5";
            if (!use_avx2) {
                p.keypair    = pqcrystals_dilithium5_ref_keypair;
                p.sign_sig   = pqcrystals_dilithium5_ref_signature;
                p.verify_sig = pqcrystals_dilithium5_ref_verify;
            } else {
                p.keypair    = pqcrystals_dilithium5_avx2_keypair;
                p.sign_sig   = pqcrystals_dilithium5_avx2_signature;
                p.verify_sig = pqcrystals_dilithium5_avx2_verify;
            }
            break;
        default:
            throw std::invalid_argument("Invalid Dilithium mode: must be 2, 3, or 5");
    }
    return p;
}
