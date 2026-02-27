#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <ostream>
#include <istream>
#include <stdexcept>
#include "base64.hpp"

// Bundle format v2 (binary layout, base64-encoded as a single line, no PEM headers):
//
//   [4]   magic:   'L' 'U' 'K' 'B'
//   [1]   version: 0x02
//   [2]   level:   512 / 768 / 1024  (uint16_t, little-endian)
//   [16]  salt:    PBKDF2 salt (16 bytes; random in password-mode; all-zeros in --pk/--sk mode)
//   [N]   ct:      Kyber KEM ciphertext (N = 768 / 1088 / 1568)
//   [12]  nonce:   AES-GCM nonce
//   [16]  tag:     AES-GCM authentication tag
//   [M]   body:    AES-256-GCM ciphertext (= len(plaintext))

static const uint8_t BUNDLE_MAGIC[4]   = { 'L', 'U', 'K', 'B' };
static const uint8_t BUNDLE_VERSION    = 0x02;
static const size_t  BUNDLE_SALT_LEN   = 16;

inline size_t ct_bytes_for_level(int level) {
    switch (level) {
        case  512: return  768;
        case  768: return 1088;
        case 1024: return 1568;
        default: throw std::invalid_argument("Invalid level for bundle");
    }
}

// Write a complete bundle as a base64 line to out (followed by '\n').
// nonce_tag_body = nonce(12) || tag(16) || ciphertext(M) as returned by aes256gcm_encrypt.
// salt must be exactly BUNDLE_SALT_LEN (16) bytes.
inline void bundle_write(std::ostream& out,
                         int level,
                         const std::vector<uint8_t>& salt,
                         const std::vector<uint8_t>& ct,
                         const std::vector<uint8_t>& nonce_tag_body)
{
    if (salt.size() != BUNDLE_SALT_LEN)
        throw std::invalid_argument("bundle_write: salt must be 16 bytes");

    uint16_t lev16 = static_cast<uint16_t>(level);

    std::vector<uint8_t> buf;
    buf.reserve(4 + 1 + 2 + BUNDLE_SALT_LEN + ct.size() + nonce_tag_body.size());
    buf.insert(buf.end(), BUNDLE_MAGIC, BUNDLE_MAGIC + 4);
    buf.push_back(BUNDLE_VERSION);
    const uint8_t* lev_bytes = reinterpret_cast<const uint8_t*>(&lev16);
    buf.push_back(lev_bytes[0]);
    buf.push_back(lev_bytes[1]);
    buf.insert(buf.end(), salt.begin(), salt.end());
    buf.insert(buf.end(), ct.begin(), ct.end());
    buf.insert(buf.end(), nonce_tag_body.begin(), nonce_tag_body.end());

    std::string b64 = base64_encode(buf.data(), buf.size());
    out << b64 << '\n';
    if (!out) throw std::runtime_error("Write error on bundle output");
}

struct BundleData {
    int                  level;
    std::vector<uint8_t> salt;           // 16 bytes
    std::vector<uint8_t> ct;
    std::vector<uint8_t> nonce_tag_body;
};

// Read a base64-encoded v2 bundle from in.
inline BundleData bundle_read(std::istream& in) {
    std::string raw(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>()
    );
    // Strip trailing whitespace
    while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r' || raw.back() == ' '))
        raw.pop_back();

    std::vector<uint8_t> bin;
    try {
        bin = base64_decode(raw);
    } catch (const std::exception&) {
        throw std::runtime_error("Not a LUKB bundle (base64 decode failed)");
    }

    const size_t hdr_size = 4 + 1 + 2 + BUNDLE_SALT_LEN;  // 23 bytes

    if (bin.size() < hdr_size)
        throw std::runtime_error("Not a LUKB bundle (too short)");

    if (std::memcmp(bin.data(), BUNDLE_MAGIC, 4) != 0)
        throw std::runtime_error("Not a LUKB bundle (bad magic)");

    if (bin[4] != BUNDLE_VERSION)
        throw std::runtime_error("Unsupported bundle version");

    uint16_t lev16;
    std::memcpy(&lev16, bin.data() + 5, 2);
    int level = static_cast<int>(lev16);

    std::vector<uint8_t> salt(bin.begin() + 7, bin.begin() + 7 + BUNDLE_SALT_LEN);

    size_t ct_len = ct_bytes_for_level(level);  // throws on bad level
    if (bin.size() < hdr_size + ct_len)
        throw std::runtime_error("Truncated bundle ciphertext field");

    std::vector<uint8_t> ct(bin.begin() + hdr_size, bin.begin() + hdr_size + ct_len);
    std::vector<uint8_t> nonce_tag_body(bin.begin() + hdr_size + ct_len, bin.end());

    return BundleData{ level, std::move(salt), std::move(ct), std::move(nonce_tag_body) };
}
