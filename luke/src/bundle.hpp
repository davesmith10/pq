#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <stdexcept>

// Bundle file format (all integers little-endian):
//
//   [4]  magic:   'L' 'U' 'K' 'B'
//   [1]  version: 0x01
//   [2]  level:   512 / 768 / 1024  (uint16_t)
//   [N]  ct:      Kyber KEM ciphertext (N = 768 / 1088 / 1568)
//   [12] nonce:   AES-GCM nonce
//   [16] tag:     AES-GCM authentication tag
//   [M]  body:    AES-256-GCM ciphertext (= len(plaintext))

static const uint8_t BUNDLE_MAGIC[4]   = { 'L', 'U', 'K', 'B' };
static const uint8_t BUNDLE_VERSION    = 0x01;

inline size_t ct_bytes_for_level(int level) {
    switch (level) {
        case  512: return  768;
        case  768: return 1088;
        case 1024: return 1568;
        default: throw std::invalid_argument("Invalid level for bundle");
    }
}

// Write a complete bundle to disk.
// nonce_tag_body = nonce(12) || tag(16) || ciphertext(M) as returned by aes256gcm_encrypt.
inline void bundle_write(const std::string& path,
                         int level,
                         const std::vector<uint8_t>& ct,
                         const std::vector<uint8_t>& nonce_tag_body)
{
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open bundle for writing: " + path);

    uint16_t lev16 = static_cast<uint16_t>(level);

    f.write(reinterpret_cast<const char*>(BUNDLE_MAGIC), 4);
    f.write(reinterpret_cast<const char*>(&BUNDLE_VERSION), 1);
    f.write(reinterpret_cast<const char*>(&lev16), 2);
    f.write(reinterpret_cast<const char*>(ct.data()),
            static_cast<std::streamsize>(ct.size()));
    f.write(reinterpret_cast<const char*>(nonce_tag_body.data()),
            static_cast<std::streamsize>(nonce_tag_body.size()));

    if (!f) throw std::runtime_error("Write error on bundle: " + path);
}

struct BundleHeader {
    int                  level;
    std::vector<uint8_t> ct;
};

// Read the header (magic, version, level, ct) from an open stream.
// Stream is left positioned at the start of nonce_tag_ciphertext.
inline BundleHeader bundle_read_header(std::ifstream& f) {
    uint8_t magic[4];
    f.read(reinterpret_cast<char*>(magic), 4);
    if (!f || std::memcmp(magic, BUNDLE_MAGIC, 4) != 0)
        throw std::runtime_error("Not a LUKB bundle (bad magic)");

    uint8_t version;
    f.read(reinterpret_cast<char*>(&version), 1);
    if (!f || version != BUNDLE_VERSION)
        throw std::runtime_error("Unsupported bundle version");

    uint16_t lev16;
    f.read(reinterpret_cast<char*>(&lev16), 2);
    if (!f) throw std::runtime_error("Truncated bundle header");
    int level = static_cast<int>(lev16);

    size_t ct_len = ct_bytes_for_level(level);
    std::vector<uint8_t> ct(ct_len);
    f.read(reinterpret_cast<char*>(ct.data()), static_cast<std::streamsize>(ct_len));
    if (!f) throw std::runtime_error("Truncated bundle ciphertext field");

    return BundleHeader{ level, std::move(ct) };
}

// Read the rest of the bundle (nonce + tag + body) after bundle_read_header.
inline std::vector<uint8_t> bundle_read_body(std::ifstream& f) {
    // Read to end of file
    std::vector<uint8_t> body(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>()
    );
    return body;
}
