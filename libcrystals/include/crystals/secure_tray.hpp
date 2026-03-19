#pragma once
#include <crystals/tray.hpp>
#include <vector>
#include <cstdint>
#include <string>

struct ScryptParams {
    std::vector<uint8_t> salt;
    int n_log2 = 19;
    int r = 8;
    int p = 1;
};

struct KemBlock {
    std::vector<uint8_t> nonce;  // 12 bytes
    std::vector<uint8_t> tag;    // 16 bytes
    std::vector<uint8_t> ct;     // 32 bytes
};

struct EncryptionEnvelope {
    ScryptParams scrypt;
    KemBlock kem;
};

struct SecureTray : public Tray {
    EncryptionEnvelope enc;
    SecureTray() { type_str = "secure-tray"; }
};

// YAML I/O — load a plain (unencrypted) tray from a YAML file.
// Throws std::runtime_error if the file is already a secure-tray.
Tray        load_tray_yaml       (const std::string& path);

// Load an encrypted secure-tray from a YAML file.
// Throws std::runtime_error if the file is not a secure-tray.
SecureTray  load_secure_tray_yaml(const std::string& path);

// Emit an encrypted secure-tray as a YAML string.
std::string emit_secure_tray_yaml(const SecureTray& st);

// Core crypto — no interactive I/O, no file access.
// Throws std::runtime_error on failure (bad UUID, crypto error, etc.).
SecureTray protect_tray  (const Tray&       tray,   const char* passwd, size_t passwd_len);
Tray       unprotect_tray(const SecureTray& st,     const char* passwd, size_t passwd_len);
