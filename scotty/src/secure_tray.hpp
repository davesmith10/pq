#pragma once
#include "tray.hpp"
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
};

// YAML I/O
Tray        load_tray_yaml       (const std::string& path);
SecureTray  load_secure_tray_yaml(const std::string& path);
std::string emit_secure_tray_yaml(const SecureTray& st);

// CLI commands
int cmd_protect  (int argc, char* argv[]);
int cmd_unprotect(int argc, char* argv[]);
