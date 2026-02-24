#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>

// ── extern "C" declarations for all 18 Kyber API functions ───────────────────

extern "C" {

// ── ref ──────────────────────────────────────────────────────────────────────
int pqcrystals_kyber512_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber512_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber512_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqcrystals_kyber512_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber512_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqcrystals_kyber768_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber768_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

int pqcrystals_kyber1024_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber1024_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqcrystals_kyber1024_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber1024_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

// ── avx2 ─────────────────────────────────────────────────────────────────────
int pqcrystals_kyber512_avx2_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber512_avx2_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber512_avx2_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqcrystals_kyber512_avx2_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber512_avx2_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

int pqcrystals_kyber768_avx2_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber768_avx2_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber768_avx2_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqcrystals_kyber768_avx2_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber768_avx2_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

int pqcrystals_kyber1024_avx2_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber1024_avx2_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber1024_avx2_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqcrystals_kyber1024_avx2_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber1024_avx2_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

} // extern "C"

// ── KyberParams ──────────────────────────────────────────────────────────────

struct KyberParams {
    int    level;      // 512, 768, or 1024
    bool   avx2;       // true = AVX2 impl, false = ref impl
    size_t pk_bytes;
    size_t sk_bytes;
    size_t ct_bytes;
    size_t ss_bytes;
};

inline KyberParams make_params(int level, bool use_avx2) {
    KyberParams p;
    p.level   = level;
    p.avx2    = use_avx2;
    p.ss_bytes = 32;

    switch (level) {
        case 512:
            p.pk_bytes = 800;
            p.sk_bytes = 1632;
            p.ct_bytes = 768;
            break;
        case 768:
            p.pk_bytes = 1184;
            p.sk_bytes = 2400;
            p.ct_bytes = 1088;
            break;
        case 1024:
            p.pk_bytes = 1568;
            p.sk_bytes = 3168;
            p.ct_bytes = 1568;
            break;
        default:
            throw std::invalid_argument("Invalid Kyber level: must be 512, 768, or 1024");
    }
    return p;
}
