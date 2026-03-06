#include <crystals/token_format.hpp>
#include <crystals/tray_reader.hpp>
#include <crystals/ec_sig.hpp>
#include <crystals/hyke_format.hpp>   // for parse_uuid()

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <stdexcept>

// ── Helpers ───────────────────────────────────────────────────────────────────

// Find the ECDSA P-256 signature slot in a tray
static const Slot* find_ecdsa_p256_slot(const Tray& tray) {
    for (const auto& s : tray.slots) {
        if (s.alg_name == "ECDSA P-256")
            return &s;
    }
    return nullptr;
}

// Read entire stdin or a named file as text
static std::string read_text_input(const std::string& path) {
    if (path.empty()) {
        return std::string(std::istreambuf_iterator<char>(std::cin),
                           std::istreambuf_iterator<char>());
    }
    std::ifstream f(path);
    if (!f)
        throw std::runtime_error("Cannot open file: " + path);
    return std::string(std::istreambuf_iterator<char>(f),
                       std::istreambuf_iterator<char>());
}

// ── cmd_gentok ────────────────────────────────────────────────────────────────

void cmd_gentok(const std::string& tray_path,
                const std::string& data_str,
                int64_t ttl_seconds)
{
    // Validate data length
    if (data_str.empty() || data_str.size() > 256) {
        std::cerr << "Error: --data must be 1–256 bytes\n";
        std::exit(1);
    }

    // Load tray
    Tray tray;
    try {
        tray = load_tray(tray_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: cannot load tray: " << e.what() << "\n";
        std::exit(3);
    }

    // Require level2 tray (P-256 + Kyber512 + ECDSA P-256 + Dilithium2)
    if (tray.tray_type != TrayType::Level2) {
        std::cerr << "Error: gentok requires a level2 tray (P-256 + ECDSA P-256); "
                  << "got '" << tray.type_str << "'\n";
        std::exit(1);
    }

    // Find ECDSA P-256 signing slot with sk
    const Slot* sig_slot = find_ecdsa_p256_slot(tray);
    if (!sig_slot) {
        std::cerr << "Error: tray has no ECDSA P-256 signature slot\n";
        std::exit(1);
    }
    if (sig_slot->sk.empty()) {
        std::cerr << "Error: ECDSA P-256 slot has no secret key (public-only tray?)\n";
        std::exit(1);
    }

    // Build token
    Token tok;
    tok.data.assign(data_str.begin(), data_str.end());
    tok.issued_at  = (int64_t)std::time(nullptr);
    tok.expires_at = tok.issued_at + ttl_seconds;
    tok.algorithm  = kTokenAlgECDSAP256;

    try {
        parse_uuid(tray.id, tok.tray_uuid);
    } catch (const std::exception& e) {
        std::cerr << "Error: failed to parse tray UUID: " << e.what() << "\n";
        std::exit(2);
    }

    // Sign canonical bytes
    auto canonical = token_canonical_bytes(tok);
    try {
        ec_sig::sign("ECDSA P-256", sig_slot->sk, canonical, tok.signature);
    } catch (const std::exception& e) {
        std::cerr << "Error: signing failed: " << e.what() << "\n";
        std::exit(2);
    }

    // Pack and armor to stdout
    auto wire = token_pack(tok);
    std::cout << token_armor(wire);
}

// ── cmd_valtok ────────────────────────────────────────────────────────────────

void cmd_valtok(const std::string& tray_path,
                const std::string& token_file)
{
    // Read token text
    std::string text;
    try {
        text = read_text_input(token_file);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        std::exit(3);
    }

    // Dearmor
    std::vector<uint8_t> wire;
    try {
        wire = token_dearmor(text);
    } catch (const std::exception& e) {
        std::cerr << "Error: failed to dearmor token: " << e.what() << "\n";
        std::exit(2);
    }

    // Unpack (structural validation)
    Token tok;
    try {
        tok = token_unpack(wire);
    } catch (const std::exception& e) {
        std::cerr << "Error: invalid token: " << e.what() << "\n";
        std::exit(2);
    }

    // Check time bounds
    int64_t now = (int64_t)std::time(nullptr);
    if (now < tok.issued_at) {
        std::cerr << "Error: token is not yet valid (issued in the future)\n";
        std::exit(2);
    }
    if (now >= tok.expires_at) {
        std::cerr << "Error: token has expired\n";
        std::exit(2);
    }

    // Load tray
    Tray tray;
    try {
        tray = load_tray(tray_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: cannot load tray: " << e.what() << "\n";
        std::exit(3);
    }

    // Find ECDSA P-256 slot (pk sufficient for verify)
    const Slot* sig_slot = find_ecdsa_p256_slot(tray);
    if (!sig_slot) {
        std::cerr << "Error: tray has no ECDSA P-256 signature slot\n";
        std::exit(1);
    }

    // Verify UUID matches
    uint8_t expected_uuid[16];
    try {
        parse_uuid(tray.id, expected_uuid);
    } catch (const std::exception& e) {
        std::cerr << "Error: failed to parse tray UUID: " << e.what() << "\n";
        std::exit(2);
    }
    if (std::memcmp(tok.tray_uuid, expected_uuid, 16) != 0) {
        std::cerr << "Error: token tray UUID does not match supplied tray\n";
        std::exit(2);
    }

    // Verify signature
    auto canonical = token_canonical_bytes(tok);
    try {
        if (!ec_sig::verify("ECDSA P-256", sig_slot->pk, canonical, tok.signature)) {
            std::cerr << "Error: token signature INVALID\n";
            std::exit(2);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: signature verification failed: " << e.what() << "\n";
        std::exit(2);
    }

    // Write data to stdout
    std::cout.write((const char*)tok.data.data(), (std::streamsize)tok.data.size());
}
