#include "tray.hpp"
#include "ec_ops.hpp"
#include "kyber_ops.hpp"
#include "dilithium_ops.hpp"
#include "blake3.h"
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <stdexcept>
#include <string>

// ── UUID derivation ───────────────────────────────────────────────────────────
// Derives a UUID v8 deterministically from the public keys in all slots using
// BLAKE3 key-derivation mode.  Input: for each slot, length-prefixed alg_name
// then length-prefixed pk (uint32_t LE lengths).  Output: 16-byte digest with
// version nibble set to 8 and variant bits set to 10xxxxxx (RFC 9562).

static std::string derive_uuid(const std::vector<Slot>& slots) {
    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, "Crystals scotty tray-uuid v1");

    for (const auto& slot : slots) {
        // Length-prefix the algorithm name (little-endian uint32_t)
        uint32_t name_len = static_cast<uint32_t>(slot.alg_name.size());
        uint8_t  name_len_le[4] = {
            static_cast<uint8_t>( name_len        & 0xFF),
            static_cast<uint8_t>((name_len >>  8) & 0xFF),
            static_cast<uint8_t>((name_len >> 16) & 0xFF),
            static_cast<uint8_t>((name_len >> 24) & 0xFF),
        };
        blake3_hasher_update(&h, name_len_le, 4);
        blake3_hasher_update(&h, slot.alg_name.data(), slot.alg_name.size());

        // Length-prefix the public key (little-endian uint32_t)
        uint32_t pk_len = static_cast<uint32_t>(slot.pk.size());
        uint8_t  pk_len_le[4] = {
            static_cast<uint8_t>( pk_len        & 0xFF),
            static_cast<uint8_t>((pk_len >>  8) & 0xFF),
            static_cast<uint8_t>((pk_len >> 16) & 0xFF),
            static_cast<uint8_t>((pk_len >> 24) & 0xFF),
        };
        blake3_hasher_update(&h, pk_len_le, 4);
        blake3_hasher_update(&h, slot.pk.data(), slot.pk.size());
    }

    uint8_t out[16];
    blake3_hasher_finalize(&h, out, 16);

    // UUID v8 bit-twiddling (RFC 9562)
    out[6] = (out[6] & 0x0F) | 0x80;  // version nibble = 8
    out[8] = (out[8] & 0x3F) | 0x80;  // variant = 10xxxxxx

    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        out[0], out[1], out[2],  out[3],
        out[4], out[5],
        out[6], out[7],
        out[8], out[9],
        out[10], out[11], out[12], out[13], out[14], out[15]);
    return std::string(buf);
}

// ── Timestamps ────────────────────────────────────────────────────────────────

static std::string iso8601_now() {
    std::time_t t = std::time(nullptr);
    struct tm* gmt = std::gmtime(&t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmt);
    return std::string(buf);
}

// Add `years` to an ISO 8601 UTC timestamp string (just increments the year).
static std::string add_years(const std::string& ts, int years) {
    // ts format: "YYYY-MM-DDTHH:MM:SSZ"
    int year = std::stoi(ts.substr(0, 4)) + years;
    return std::to_string(year) + ts.substr(4);
}

// ── Slot factories ────────────────────────────────────────────────────────────

static Slot make_ec_slot(const std::string& name, ec::Algorithm alg) {
    Slot s;
    s.alg_name = name;
    auto kp = ec::keygen(alg);
    s.pk = std::move(kp.pk);
    s.sk = std::move(kp.sk);
    return s;
}

static Slot make_kyber_slot(const std::string& name, int level) {
    Slot s;
    s.alg_name = name;
    kyber::keygen(level, s.pk, s.sk);
    return s;
}

static Slot make_dilithium_slot(const std::string& name, int mode) {
    Slot s;
    s.alg_name = name;
    dilithium::keygen(mode, s.pk, s.sk);
    return s;
}

// ── make_tray ─────────────────────────────────────────────────────────────────

Tray make_tray(TrayType t, const std::string& alias)
{
    Tray tray;
    tray.version   = 1;
    tray.alias     = alias;
    tray.tray_type = t;
    tray.created   = iso8601_now();
    tray.expires   = add_years(tray.created, 2);

    tray.profile_group = "crystals";

    switch (t) {
        case TrayType::Level0:
            tray.type_str = "level0";
            tray.slots.push_back(make_ec_slot("X25519",  ec::Algorithm::X25519));
            tray.slots.push_back(make_ec_slot("Ed25519", ec::Algorithm::Ed25519));
            break;

        case TrayType::Level1:
            tray.type_str = "level1";
            tray.slots.push_back(make_kyber_slot("Kyber512",    512));
            tray.slots.push_back(make_dilithium_slot("Dilithium2", 2));
            break;

        // Slot ordering: KEM-classical, KEM-PQ, Sig-classical, Sig-PQ
        case TrayType::Level2_25519:
            tray.type_str = "level2-25519";
            tray.slots.push_back(make_ec_slot("X25519",      ec::Algorithm::X25519));
            tray.slots.push_back(make_kyber_slot("Kyber512", 512));
            tray.slots.push_back(make_ec_slot("Ed25519",     ec::Algorithm::Ed25519));
            tray.slots.push_back(make_dilithium_slot("Dilithium2", 2));
            break;

        case TrayType::Level2:
            tray.type_str = "level2";
            tray.slots.push_back(make_ec_slot("P-256",          ec::Algorithm::P256));
            tray.slots.push_back(make_kyber_slot("Kyber512",     512));
            tray.slots.push_back(make_ec_slot("ECDSA P-256",    ec::Algorithm::P256));
            tray.slots.push_back(make_dilithium_slot("Dilithium2", 2));
            break;

        case TrayType::Level3:
            tray.type_str = "level3";
            tray.slots.push_back(make_ec_slot("P-384",          ec::Algorithm::P384));
            tray.slots.push_back(make_kyber_slot("Kyber768",     768));
            tray.slots.push_back(make_ec_slot("ECDSA P-384",    ec::Algorithm::P384));
            tray.slots.push_back(make_dilithium_slot("Dilithium3", 3));
            break;

        case TrayType::Level5:
            tray.type_str = "level5";
            tray.slots.push_back(make_ec_slot("P-521",          ec::Algorithm::P521));
            tray.slots.push_back(make_kyber_slot("Kyber1024",   1024));
            tray.slots.push_back(make_ec_slot("ECDSA P-521",    ec::Algorithm::P521));
            tray.slots.push_back(make_dilithium_slot("Dilithium5", 5));
            break;
    }

    tray.id = derive_uuid(tray.slots);
    return tray;
}

// ── make_public_tray ──────────────────────────────────────────────────────────

Tray make_public_tray(const Tray& src) {
    Tray pub    = src;
    pub.alias   = src.alias + ".pub";
    pub.is_public = true;
    for (auto& slot : pub.slots)
        slot.sk.clear();
    pub.id = derive_uuid(pub.slots);   // same pk as src → same UUID
    return pub;
}
