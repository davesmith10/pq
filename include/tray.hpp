#pragma once
#include <string>
#include <vector>
#include <cstdint>

enum class TrayType { Level0, Level1, Level2_25519, Level2, Level3, Level5 };

struct Slot {
    std::string alg_name;       // e.g. "X25519", "Kyber768", "ECDSA P-384", "Dilithium3"
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;    // empty if public-only tray
};

struct Tray {
    int version = 1;
    std::string alias;
    TrayType tray_type;
    std::string profile_group;  // always "crystals"
    std::string type_str;       // "level0", "level1", "level2-25519", "level2", "level3", "level5"
    std::string id;             // UUID v8
    bool is_public = false;
    std::vector<Slot> slots;
    std::string created;        // ISO 8601 UTC
    std::string expires;        // ISO 8601 UTC (created + 2 years)
};

// Generate a full tray with keyed material.
Tray make_tray(TrayType t, const std::string& alias);

// Copy src, clear all sk fields, assign a fresh UUID, append ".pub" to alias.
Tray make_public_tray(const Tray& src);
