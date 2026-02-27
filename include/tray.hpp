#pragma once
#include <string>
#include <vector>
#include <cstdint>

enum class TrayType { Level2, Level2NIST, Level3NIST, Level5NIST };

struct Slot {
    std::string alg_name;       // e.g. "X25519", "Kyber768", "ECDSA P-384", "Dilithium3"
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;    // empty if public-only tray
};

struct Tray {
    int version = 1;
    std::string alias;
    TrayType tray_type;
    std::string type_str;       // "level2", "level2nist", "level3nist", "level5nist"
    std::string id;             // UUID v4
    bool is_public = false;
    std::vector<Slot> slots;
    std::string created;        // ISO 8601 UTC
    std::string expires;        // ISO 8601 UTC (created + 2 years)
};

// Generate a full tray with keyed material.
// classic_only: include only KEM-classical and Sig-classical slots
// pq_only:      include only KEM-PQ and Sig-PQ slots
// Neither flag: all four slots
Tray make_tray(TrayType t, const std::string& alias,
               bool classic_only, bool pq_only);
