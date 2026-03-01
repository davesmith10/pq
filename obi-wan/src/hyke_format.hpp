#pragma once
#include "tray.hpp"
#include "base64.hpp"
#include <vector>
#include <cstdint>
#include <string>
#include <stdexcept>
#include <cstring>
#include <sstream>
#include <iomanip>

// HYKE Wire Format (binary, before base64 armoring):
//
// Offset  Size  Field
// ------  ----  -----
//  0       4    Magic: 0x48594B45 ("HYKE")
//  4       2    Version: 0x0001
//  6       1    TrayID: 0x01=Level2_25519, 0x02=Level2, 0x03=Level3, 0x04=Level5
//  7       1    Flags: 0x00 (reserved)
//  8       4    header_len  (total bytes from offset 0 to end of sig_pq bytes)
// 12       4    payload_len (bytes of encrypted payload)
// 16      16    tray_uuid   (binary: parse 36-char UUID string → 16 bytes)
// 32      32    salt        (random per file)
// 64       4    ct_classical_len
// 68       4    ct_pq_len
// 72       4    sig_classical_len
// 76       4    sig_pq_len
// 80       N    ct_classical bytes
// 80+N     M    ct_pq bytes
//          P    sig_classical bytes
//          Q    sig_pq bytes
// [header ends here]
//          R    encrypted_payload (nonce12 + tag16 + ciphertext)

struct HykeHeader {
    uint8_t  tray_id = 0;
    uint8_t  tray_uuid[16] = {};
    uint8_t  salt[32] = {};
    std::vector<uint8_t> ct_classical;
    std::vector<uint8_t> ct_pq;
    std::vector<uint8_t> sig_classical;
    std::vector<uint8_t> sig_pq;
};

static constexpr char kHykeArmorBegin[] = "-----BEGIN HYKE SIGNED FILE-----";
static constexpr char kHykeArmorEnd[]   = "-----END HYKE SIGNED FILE-----";

// ── TrayID mapping ────────────────────────────────────────────────────────────

inline uint8_t tray_id_byte(TrayType t) {
    switch (t) {
        case TrayType::Level2_25519: return 0x01;
        case TrayType::Level2:       return 0x02;
        case TrayType::Level3:       return 0x03;
        case TrayType::Level5:       return 0x04;
        default: throw std::invalid_argument("Unknown TrayType");
    }
}

inline TrayType tray_type_from_id(uint8_t id) {
    switch (id) {
        case 0x01: return TrayType::Level2_25519;
        case 0x02: return TrayType::Level2;
        case 0x03: return TrayType::Level3;
        case 0x04: return TrayType::Level5;
        default: throw std::runtime_error("Unknown HYKE TrayID: " + std::to_string((int)id));
    }
}

// ── UUID parsing ──────────────────────────────────────────────────────────────

// Parse 36-char RFC 4122 UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) to 16 bytes
inline void parse_uuid(const std::string& uuid_str, uint8_t uuid_bytes[16]) {
    std::string hex;
    hex.reserve(32);
    for (char c : uuid_str) {
        if (c != '-') hex += c;
    }
    if (hex.size() != 32)
        throw std::runtime_error("Invalid UUID (expected 32 hex chars without dashes): " + uuid_str);
    for (int i = 0; i < 16; ++i) {
        unsigned int byte_val = 0;
        std::istringstream ss(hex.substr(i * 2, 2));
        ss >> std::hex >> byte_val;
        uuid_bytes[i] = (uint8_t)byte_val;
    }
}

// ── Wire format helpers ───────────────────────────────────────────────────────

static inline void hyke_push_u16be(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back((v >> 0) & 0xFF);
}

static inline void hyke_push_u32be(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back((v >> 24) & 0xFF);
    buf.push_back((v >> 16) & 0xFF);
    buf.push_back((v >>  8) & 0xFF);
    buf.push_back((v >>  0) & 0xFF);
}

static inline uint16_t hyke_read_u16be(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static inline uint32_t hyke_read_u32be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) | (uint32_t)p[3];
}

// ── Partial header (for signing) ─────────────────────────────────────────────

// Build the first 80 + ct_classical.size() + ct_pq.size() bytes of the header.
// These bytes are committed to by the signatures.
// sig_cl_len and sig_pq_len are the final (known) signature sizes — they appear
// as length fields in the header but the actual sig bytes come AFTER these bytes.
inline std::vector<uint8_t> hyke_partial_header(
    const HykeHeader& hdr,
    uint32_t payload_len,
    uint32_t sig_cl_len,
    uint32_t sig_pq_len)
{
    const uint32_t header_len = 80
                              + (uint32_t)hdr.ct_classical.size()
                              + (uint32_t)hdr.ct_pq.size()
                              + sig_cl_len
                              + sig_pq_len;

    std::vector<uint8_t> buf;
    buf.reserve(80 + hdr.ct_classical.size() + hdr.ct_pq.size());

    // Magic "HYKE" (4 bytes)
    buf.push_back('H'); buf.push_back('Y'); buf.push_back('K'); buf.push_back('E');

    // Version 0x0001 (2 bytes big-endian)
    hyke_push_u16be(buf, 0x0001);

    // TrayID (1 byte) + Flags 0x00 (1 byte)
    buf.push_back(hdr.tray_id);
    buf.push_back(0x00);

    // header_len (4 bytes)
    hyke_push_u32be(buf, header_len);

    // payload_len (4 bytes)
    hyke_push_u32be(buf, payload_len);

    // tray_uuid (16 bytes)
    buf.insert(buf.end(), hdr.tray_uuid, hdr.tray_uuid + 16);

    // salt (32 bytes)
    buf.insert(buf.end(), hdr.salt, hdr.salt + 32);

    // ct_classical_len (4 bytes)
    hyke_push_u32be(buf, (uint32_t)hdr.ct_classical.size());

    // ct_pq_len (4 bytes)
    hyke_push_u32be(buf, (uint32_t)hdr.ct_pq.size());

    // sig_classical_len (4 bytes)
    hyke_push_u32be(buf, sig_cl_len);

    // sig_pq_len (4 bytes)
    hyke_push_u32be(buf, sig_pq_len);

    // ct_classical bytes
    buf.insert(buf.end(), hdr.ct_classical.begin(), hdr.ct_classical.end());

    // ct_pq bytes
    buf.insert(buf.end(), hdr.ct_pq.begin(), hdr.ct_pq.end());

    return buf;
}

// ── Pack / Unpack ─────────────────────────────────────────────────────────────

// Pack complete HYKE wire bytes: full header (partial + sigs) + payload.
// hdr.sig_classical and hdr.sig_pq must be populated before calling.
inline std::vector<uint8_t> hyke_pack(const HykeHeader& hdr,
                                       const std::vector<uint8_t>& payload)
{
    auto partial = hyke_partial_header(hdr, (uint32_t)payload.size(),
                                       (uint32_t)hdr.sig_classical.size(),
                                       (uint32_t)hdr.sig_pq.size());

    std::vector<uint8_t> wire;
    wire.reserve(partial.size() +
                 hdr.sig_classical.size() +
                 hdr.sig_pq.size() +
                 payload.size());

    wire.insert(wire.end(), partial.begin(),          partial.end());
    wire.insert(wire.end(), hdr.sig_classical.begin(), hdr.sig_classical.end());
    wire.insert(wire.end(), hdr.sig_pq.begin(),        hdr.sig_pq.end());
    wire.insert(wire.end(), payload.begin(),           payload.end());

    return wire;
}

// Unpack: parse wire bytes into HykeHeader + payload.
// Throws std::runtime_error on malformed input.
inline HykeHeader hyke_unpack(const std::vector<uint8_t>& wire,
                                std::vector<uint8_t>& payload_out)
{
    static const size_t kMinWire = 80; // fixed header fields only
    if (wire.size() < kMinWire)
        throw std::runtime_error("HYKE wire too short");

    const uint8_t* p   = wire.data();
    const uint8_t* end = wire.data() + wire.size();

    // Magic
    if (std::memcmp(p, "HYKE", 4) != 0)
        throw std::runtime_error("HYKE wire: invalid magic");
    p += 4;

    // Version
    uint16_t version = hyke_read_u16be(p); p += 2;
    if (version != 0x0001)
        throw std::runtime_error("HYKE wire: unsupported version " + std::to_string(version));

    HykeHeader hdr;
    hdr.tray_id = *p++;
    p++;  // flags (reserved, skip)

    uint32_t header_len  = hyke_read_u32be(p); p += 4;
    uint32_t payload_len = hyke_read_u32be(p); p += 4;

    // UUID (16 bytes)
    if (p + 16 > end) throw std::runtime_error("HYKE wire: truncated uuid");
    std::memcpy(hdr.tray_uuid, p, 16); p += 16;

    // Salt (32 bytes)
    if (p + 32 > end) throw std::runtime_error("HYKE wire: truncated salt");
    std::memcpy(hdr.salt, p, 32); p += 32;

    // Length fields (4 × 4 bytes)
    if (p + 16 > end) throw std::runtime_error("HYKE wire: truncated length fields");
    uint32_t ct_cl_len  = hyke_read_u32be(p); p += 4;
    uint32_t ct_pq_len  = hyke_read_u32be(p); p += 4;
    uint32_t sig_cl_len = hyke_read_u32be(p); p += 4;
    uint32_t sig_pq_len = hyke_read_u32be(p); p += 4;

    // Validate header_len
    uint64_t expected_hdr = 80ULL + ct_cl_len + ct_pq_len + sig_cl_len + sig_pq_len;
    if ((uint64_t)header_len != expected_hdr)
        throw std::runtime_error("HYKE wire: header_len inconsistent with field lengths");
    if ((size_t)header_len > wire.size())
        throw std::runtime_error("HYKE wire: header_len exceeds wire size");

    const uint8_t* header_end = wire.data() + header_len;

    // ct_classical
    if (p + ct_cl_len > header_end) throw std::runtime_error("HYKE wire: truncated ct_classical");
    hdr.ct_classical.assign(p, p + ct_cl_len); p += ct_cl_len;

    // ct_pq
    if (p + ct_pq_len > header_end) throw std::runtime_error("HYKE wire: truncated ct_pq");
    hdr.ct_pq.assign(p, p + ct_pq_len); p += ct_pq_len;

    // sig_classical
    if (p + sig_cl_len > header_end) throw std::runtime_error("HYKE wire: truncated sig_classical");
    hdr.sig_classical.assign(p, p + sig_cl_len); p += sig_cl_len;

    // sig_pq
    if (p + sig_pq_len > header_end) throw std::runtime_error("HYKE wire: truncated sig_pq");
    hdr.sig_pq.assign(p, p + sig_pq_len); p += sig_pq_len;

    if (p != header_end)
        throw std::runtime_error("HYKE wire: header parse ended before header_end");

    // Validate total wire size
    if (wire.data() + header_len + (size_t)payload_len > end)
        throw std::runtime_error("HYKE wire: payload extends beyond wire data");

    payload_out.assign(header_end, header_end + payload_len);

    return hdr;
}

// ── Armor / Dearmor ───────────────────────────────────────────────────────────

inline std::string hyke_armor(const std::vector<uint8_t>& wire) {
    std::string b64 = base64_encode(wire.data(), wire.size());

    std::string out;
    out.reserve(sizeof(kHykeArmorBegin) + b64.size() + b64.size() / 64 + sizeof(kHykeArmorEnd) + 4);
    out += kHykeArmorBegin;
    out += '\n';

    for (size_t i = 0; i < b64.size(); i += 64) {
        out += b64.substr(i, 64);
        out += '\n';
    }

    out += kHykeArmorEnd;
    out += '\n';
    return out;
}

inline std::vector<uint8_t> hyke_dearmor(const std::string& text) {
    std::string b64;
    std::istringstream ss(text);
    std::string line;
    bool in_body = false;

    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line == kHykeArmorBegin) { in_body = true;  continue; }
        if (line == kHykeArmorEnd)   { in_body = false; continue; }
        if (in_body) b64 += line;
    }

    if (b64.empty())
        throw std::runtime_error("hyke_dearmor: no base64 data found (missing armor markers?)");

    return base64_decode(b64);
}
