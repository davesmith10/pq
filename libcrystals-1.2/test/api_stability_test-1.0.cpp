// api_stability_test.cpp — compile-time enforcement of the v1.0 public API.
//
// IMPORTANT: This file MUST compile cleanly.
// DO NOT modify it when adding features — only ADD to it.
// A compile failure here means a breaking API change was introduced.
//
// Only includes crystals/crystals.hpp — no internal headers.

#include "crystals/crystals.hpp"
#include <type_traits>

// ── TrayType enum values ──────────────────────────────────────────────────────
static_assert(std::is_same_v<decltype(TrayType::Level0), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::Level1), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::Level2_25519), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::Level2), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::Level3), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::Level5), TrayType>);

// ── Tray fields ───────────────────────────────────────────────────────────────
static_assert(std::is_same_v<decltype(std::declval<Tray>().version), int>);
static_assert(std::is_same_v<decltype(std::declval<Tray>().alias), std::string>);
static_assert(std::is_same_v<decltype(std::declval<Tray>().tray_type), TrayType>);
static_assert(std::is_same_v<decltype(std::declval<Tray>().id), std::string>);
static_assert(std::is_same_v<decltype(std::declval<Tray>().slots), std::vector<Slot>>);
static_assert(std::is_same_v<decltype(std::declval<Tray>().is_public), bool>);

// ── Slot fields ───────────────────────────────────────────────────────────────
static_assert(std::is_same_v<decltype(std::declval<Slot>().alg_name), std::string>);
static_assert(std::is_same_v<decltype(std::declval<Slot>().pk), std::vector<uint8_t>>);
static_assert(std::is_same_v<decltype(std::declval<Slot>().sk), std::vector<uint8_t>>);

// ── make_tray / make_public_tray / validate_tray_uuid ─────────────────────────
static_assert(std::is_same_v<
    decltype(&make_tray),
    Tray(*)(TrayType, const std::string&)
>, "make_tray signature changed — API break!");

static_assert(std::is_same_v<
    decltype(&make_public_tray),
    Tray(*)(const Tray&)
>, "make_public_tray signature changed — API break!");

static_assert(std::is_same_v<
    decltype(&validate_tray_uuid),
    bool(*)(const Tray&)
>, "validate_tray_uuid signature changed — API break!");

// ── SecureTray ────────────────────────────────────────────────────────────────
static_assert(std::is_base_of_v<Tray, SecureTray>, "SecureTray must extend Tray");

// ── protect_tray / unprotect_tray ─────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&protect_tray),
    SecureTray(*)(const Tray&, const char*, size_t)
>, "protect_tray signature changed — API break!");

static_assert(std::is_same_v<
    decltype(&unprotect_tray),
    Tray(*)(const SecureTray&, const char*, size_t)
>, "unprotect_tray signature changed — API break!");

// ── KDFAlg / CipherAlg enum values ───────────────────────────────────────────
static_assert(static_cast<uint8_t>(KDFAlg::SHAKE256) == 0, "KDFAlg::SHAKE256 value changed");
static_assert(static_cast<uint8_t>(KDFAlg::KMAC256)  == 1, "KDFAlg::KMAC256 value changed");
static_assert(static_cast<uint8_t>(CipherAlg::AES256GCM)        == 0, "CipherAlg::AES256GCM value changed");
static_assert(static_cast<uint8_t>(CipherAlg::ChaCha20Poly1305) == 1, "CipherAlg::ChaCha20Poly1305 value changed");

// ── WireHeader fields ─────────────────────────────────────────────────────────
static_assert(std::is_same_v<decltype(std::declval<WireHeader>().kdf), KDFAlg>);
static_assert(std::is_same_v<decltype(std::declval<WireHeader>().cipher), CipherAlg>);
static_assert(std::is_same_v<decltype(std::declval<WireHeader>().ct_classical), std::vector<uint8_t>>);
static_assert(std::is_same_v<decltype(std::declval<WireHeader>().ct_pq), std::vector<uint8_t>>);

// ── armor_pack / armor_unpack ─────────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&armor_pack),
    std::string(*)(const WireHeader&, const std::vector<uint8_t>&)
>, "armor_pack signature changed — API break!");

static_assert(std::is_same_v<
    decltype(&armor_unpack),
    WireHeader(*)(const std::string&, std::vector<uint8_t>&)
>, "armor_unpack signature changed — API break!");

// ── ec::Algorithm enum ────────────────────────────────────────────────────────
static_assert(std::is_same_v<decltype(ec::Algorithm::X25519), ec::Algorithm>);
static_assert(std::is_same_v<decltype(ec::Algorithm::Ed25519), ec::Algorithm>);
static_assert(std::is_same_v<decltype(ec::Algorithm::P256), ec::Algorithm>);
static_assert(std::is_same_v<decltype(ec::Algorithm::P384), ec::Algorithm>);
static_assert(std::is_same_v<decltype(ec::Algorithm::P521), ec::Algorithm>);

// ── ec::keygen ────────────────────────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&ec::keygen),
    ec::KeyPair(*)(ec::Algorithm)
>, "ec::keygen signature changed — API break!");

// ── ec_kem functions ──────────────────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&ec_kem::is_classical_kem),
    bool(*)(const std::string&)
>, "ec_kem::is_classical_kem signature changed");

// ── ec_sig functions ──────────────────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&ec_sig::is_classical_sig),
    bool(*)(const std::string&)
>, "ec_sig::is_classical_sig signature changed");

static_assert(std::is_same_v<
    decltype(&ec_sig::sig_bytes),
    size_t(*)(const std::string&)
>, "ec_sig::sig_bytes signature changed");

// ── dilithium::keygen ─────────────────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&dilithium::keygen),
    void(*)(int, std::vector<uint8_t>&, std::vector<uint8_t>&)
>, "dilithium::keygen signature changed — API break!");

// ── DilithiumSizes ────────────────────────────────────────────────────────────
static_assert(std::is_same_v<decltype(std::declval<DilithiumSizes>().pk_bytes), size_t>);
static_assert(std::is_same_v<decltype(std::declval<DilithiumSizes>().sk_bytes), size_t>);

// ── Dilithium sig byte constants ──────────────────────────────────────────────
static_assert(DILITHIUM2_SIG_BYTES == 2420, "DILITHIUM2_SIG_BYTES value changed");
static_assert(DILITHIUM3_SIG_BYTES == 3309, "DILITHIUM3_SIG_BYTES value changed");
static_assert(DILITHIUM5_SIG_BYTES == 4627, "DILITHIUM5_SIG_BYTES value changed");

// ── dilithium_sig functions ───────────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&dilithium_sig::is_pq_sig),
    bool(*)(const std::string&)
>, "dilithium_sig::is_pq_sig signature changed");

static_assert(std::is_same_v<
    decltype(&dilithium_sig::mode_from_alg),
    int(*)(const std::string&)
>, "dilithium_sig::mode_from_alg signature changed");

// ── kyber::keygen ─────────────────────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&kyber::keygen),
    void(*)(int, std::vector<uint8_t>&, std::vector<uint8_t>&)
>, "kyber::keygen signature changed — API break!");

// ── KyberKEMSizes ─────────────────────────────────────────────────────────────
static_assert(std::is_same_v<decltype(std::declval<KyberKEMSizes>().pk_bytes), size_t>);
static_assert(std::is_same_v<decltype(std::declval<KyberKEMSizes>().ct_bytes), size_t>);
static_assert(std::is_same_v<decltype(std::declval<KyberKEMSizes>().ss_bytes), size_t>);

// ── kyber_kem functions ───────────────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&kyber_kem::level_from_alg),
    int(*)(const std::string&)
>, "kyber_kem::level_from_alg signature changed");

// ── PwBundle fields ───────────────────────────────────────────────────────────
static_assert(std::is_same_v<decltype(std::declval<PwBundle>().level), int>);
static_assert(std::is_same_v<decltype(std::declval<PwBundle>().pk), std::vector<uint8_t>>);
static_assert(std::is_same_v<decltype(std::declval<PwBundle>().ct), std::vector<uint8_t>>);

// ── Token fields ──────────────────────────────────────────────────────────────
static_assert(std::is_same_v<decltype(std::declval<Token>().data), std::vector<uint8_t>>);
static_assert(std::is_same_v<decltype(std::declval<Token>().issued_at), int64_t>);
static_assert(std::is_same_v<decltype(std::declval<Token>().expires_at), int64_t>);
static_assert(std::is_same_v<decltype(std::declval<Token>().signature), std::vector<uint8_t>>);

// ── kTokenAlgECDSAP256 ────────────────────────────────────────────────────────
static_assert(kTokenAlgECDSAP256 == 0x03, "kTokenAlgECDSAP256 value changed");

// ── AEAD constants ────────────────────────────────────────────────────────────
static_assert(AEAD_NONCE_LEN == 12, "AEAD_NONCE_LEN value changed");
static_assert(AEAD_TAG_LEN   == 16, "AEAD_TAG_LEN value changed");

// ── load_tray / emit_tray_yaml ────────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&load_tray),
    Tray(*)(const std::string&)
>, "load_tray signature changed — API break!");

static_assert(std::is_same_v<
    decltype(&emit_tray_yaml),
    std::string(*)(const Tray&)
>, "emit_tray_yaml signature changed — API break!");

// ── base64 ────────────────────────────────────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&base64_encode),
    std::string(*)(const uint8_t*, size_t)
>, "base64_encode signature changed");

static_assert(std::is_same_v<
    decltype(&base64_decode),
    std::vector<uint8_t>(*)(const std::string&)
>, "base64_decode signature changed");

// ── All checks pass ───────────────────────────────────────────────────────────
int main() { return 0; }
