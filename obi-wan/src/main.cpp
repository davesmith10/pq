#include "tray_reader.hpp"
#include "kyber_kem.hpp"
#include "ec_kem.hpp"
#include "kdf.hpp"
#include "symmetric.hpp"
#include "armor.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <stdexcept>

// ── Usage ─────────────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    std::cerr <<
        "Usage:\n"
        "  " << prog << " encrypt --tray <file> [--kdf SHAKE|KMAC] [--cipher AES-256-GCM|ChaCha20] <target-file>\n"
        "  " << prog << " decrypt --tray <file> <target-file>\n"
        "\n"
        "  --tray   Tray file (YAML or msgpack, auto-detected)\n"
        "  --kdf    Key derivation function: SHAKE (default) or KMAC\n"
        "  --cipher Symmetric cipher: AES-256-GCM (default) or ChaCha20\n"
        "\n"
        "  encrypt: reads <target-file>, writes armored ciphertext to stdout\n"
        "  decrypt: reads armored <target-file>, writes plaintext to stdout\n"
        "\n"
        "Exit codes: 0=ok, 1=usage, 2=crypto, 3=I/O\n";
}

// ── File reading ──────────────────────────────────────────────────────────────

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot open file: " + path);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

static std::string read_file_text(const std::string& path) {
    std::ifstream f(path);
    if (!f)
        throw std::runtime_error("Cannot open file: " + path);
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

// ── Slot selection ────────────────────────────────────────────────────────────

// Find the first classical KEM slot (X25519 or P-xxx)
static const Slot* find_classical_slot(const Tray& tray) {
    for (const auto& s : tray.slots) {
        if (ec_kem::is_classical_kem(s.alg_name))
            return &s;
    }
    return nullptr;
}

// Find the first PQ KEM slot (Kyber*)
static const Slot* find_pq_slot(const Tray& tray) {
    for (const auto& s : tray.slots) {
        if (s.alg_name.substr(0, 5) == "Kyber")
            return &s;
    }
    return nullptr;
}

// ── encrypt command ───────────────────────────────────────────────────────────

static int cmd_encrypt(const std::string& tray_path,
                        const std::string& target_path,
                        KDFAlg kdf_alg,
                        CipherAlg cipher_alg)
{
    // Load tray
    Tray tray;
    try {
        tray = load_tray(tray_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: cannot load tray: " << e.what() << "\n";
        return 3;
    }

    const Slot* cl_slot = find_classical_slot(tray);
    const Slot* pq_slot = find_pq_slot(tray);

    if (!cl_slot || !pq_slot) {
        std::cerr << "Error: tray must contain both a classical KEM slot and a Kyber slot\n";
        return 1;
    }

    // Read plaintext
    std::vector<uint8_t> plaintext;
    try {
        plaintext = read_file(target_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }

    // Classical KEM encaps
    std::vector<uint8_t> ct_classical, ss_classical;
    try {
        ec_kem::encaps(cl_slot->alg_name, cl_slot->pk, ct_classical, ss_classical);
    } catch (const std::exception& e) {
        std::cerr << "Error: classical KEM encaps failed: " << e.what() << "\n";
        return 2;
    }

    // PQ KEM encaps
    int kyber_level = 0;
    std::vector<uint8_t> ct_pq, ss_pq;
    try {
        kyber_level = kyber_kem::level_from_alg(pq_slot->alg_name);
        kyber_kem::encaps(kyber_level, pq_slot->pk, ct_pq, ss_pq);
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ KEM encaps failed: " << e.what() << "\n";
        return 2;
    }

    // KDF
    std::array<uint8_t, 32> key;
    try {
        if (kdf_alg == KDFAlg::SHAKE256)
            key = derive_key_shake(ss_classical, ss_pq, ct_classical, ct_pq);
        else
            key = derive_key_kmac(ss_classical, ss_pq, ct_classical, ct_pq);
    } catch (const std::exception& e) {
        std::cerr << "Error: KDF failed: " << e.what() << "\n";
        return 2;
    }

    // Symmetric encrypt
    std::vector<uint8_t> payload;
    try {
        if (cipher_alg == CipherAlg::AES256GCM)
            payload = aes256gcm_encrypt(key.data(), plaintext);
        else
            payload = chacha20poly1305_encrypt(key.data(), plaintext);
    } catch (const std::exception& e) {
        std::cerr << "Error: encryption failed: " << e.what() << "\n";
        return 2;
    }

    // Armor and output
    WireHeader hdr;
    hdr.kdf          = kdf_alg;
    hdr.cipher       = cipher_alg;
    hdr.ct_classical = std::move(ct_classical);
    hdr.ct_pq        = std::move(ct_pq);

    std::cout << armor_pack(hdr, payload);
    return 0;
}

// ── decrypt command ───────────────────────────────────────────────────────────

static int cmd_decrypt(const std::string& tray_path,
                        const std::string& target_path)
{
    // Load tray
    Tray tray;
    try {
        tray = load_tray(tray_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: cannot load tray: " << e.what() << "\n";
        return 3;
    }

    const Slot* cl_slot = find_classical_slot(tray);
    const Slot* pq_slot = find_pq_slot(tray);

    if (!cl_slot || !pq_slot) {
        std::cerr << "Error: tray must contain both a classical KEM slot and a Kyber slot\n";
        return 1;
    }
    if (cl_slot->sk.empty() || pq_slot->sk.empty()) {
        std::cerr << "Error: tray secret keys required for decryption\n";
        return 1;
    }

    // Read armored ciphertext
    std::string armored;
    try {
        armored = read_file_text(target_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }

    // Unpack
    std::vector<uint8_t> payload;
    WireHeader hdr;
    try {
        hdr = armor_unpack(armored, payload);
    } catch (const std::exception& e) {
        std::cerr << "Error: failed to parse ciphertext: " << e.what() << "\n";
        return 3;
    }

    // Classical KEM decaps
    std::vector<uint8_t> ss_classical;
    try {
        ec_kem::decaps(cl_slot->alg_name, cl_slot->sk, hdr.ct_classical, ss_classical);
    } catch (const std::exception& e) {
        std::cerr << "Error: classical KEM decaps failed: " << e.what() << "\n";
        return 2;
    }

    // PQ KEM decaps
    std::vector<uint8_t> ss_pq;
    try {
        int kyber_level = kyber_kem::level_from_alg(pq_slot->alg_name);
        kyber_kem::decaps(kyber_level, pq_slot->sk, hdr.ct_pq, ss_pq);
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ KEM decaps failed: " << e.what() << "\n";
        return 2;
    }

    // KDF
    std::array<uint8_t, 32> key;
    try {
        if (hdr.kdf == KDFAlg::SHAKE256)
            key = derive_key_shake(ss_classical, ss_pq, hdr.ct_classical, hdr.ct_pq);
        else
            key = derive_key_kmac(ss_classical, ss_pq, hdr.ct_classical, hdr.ct_pq);
    } catch (const std::exception& e) {
        std::cerr << "Error: KDF failed: " << e.what() << "\n";
        return 2;
    }

    // Symmetric decrypt
    std::vector<uint8_t> plaintext;
    try {
        if (hdr.cipher == CipherAlg::AES256GCM)
            plaintext = aes256gcm_decrypt(key.data(), payload);
        else
            plaintext = chacha20poly1305_decrypt(key.data(), payload);
    } catch (const std::exception& e) {
        std::cerr << "Error: decryption/authentication failed: " << e.what() << "\n";
        return 2;
    }

    // Output plaintext
    std::cout.write((const char*)plaintext.data(), (std::streamsize)plaintext.size());
    return 0;
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "--help" || cmd == "-h") {
        print_usage(argv[0]);
        return 0;
    }

    if (cmd != "encrypt" && cmd != "decrypt") {
        std::cerr << "Error: unknown command '" << cmd << "'\n";
        print_usage(argv[0]);
        return 1;
    }

    // Parse shared and command-specific options
    std::string tray_path;
    std::string target_path;
    KDFAlg    kdf_alg    = KDFAlg::SHAKE256;
    CipherAlg cipher_alg = CipherAlg::AES256GCM;

    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--tray") == 0) {
            if (++i >= argc) {
                std::cerr << "Error: --tray requires a filename\n";
                return 1;
            }
            tray_path = argv[i];
        } else if (std::strcmp(argv[i], "--kdf") == 0) {
            if (++i >= argc) {
                std::cerr << "Error: --kdf requires a value\n";
                return 1;
            }
            std::string v = argv[i];
            if (v == "SHAKE" || v == "SHAKE256") {
                kdf_alg = KDFAlg::SHAKE256;
            } else if (v == "KMAC" || v == "KMAC256") {
                kdf_alg = KDFAlg::KMAC256;
            } else {
                std::cerr << "Error: unknown --kdf value '" << v << "' (must be SHAKE or KMAC)\n";
                return 1;
            }
        } else if (std::strcmp(argv[i], "--cipher") == 0) {
            if (++i >= argc) {
                std::cerr << "Error: --cipher requires a value\n";
                return 1;
            }
            std::string v = argv[i];
            if (v == "AES-256-GCM" || v == "AES") {
                cipher_alg = CipherAlg::AES256GCM;
            } else if (v == "ChaCha20" || v == "ChaCha20-Poly1305") {
                cipher_alg = CipherAlg::ChaCha20Poly1305;
            } else {
                std::cerr << "Error: unknown --cipher value '" << v
                          << "' (must be AES-256-GCM or ChaCha20)\n";
                return 1;
            }
        } else if (argv[i][0] == '-') {
            std::cerr << "Error: unknown option '" << argv[i] << "'\n";
            return 1;
        } else {
            if (!target_path.empty()) {
                std::cerr << "Error: unexpected argument '" << argv[i] << "'\n";
                return 1;
            }
            target_path = argv[i];
        }
    }

    if (tray_path.empty()) {
        std::cerr << "Error: --tray is required\n";
        return 1;
    }
    if (target_path.empty()) {
        std::cerr << "Error: <target-file> is required\n";
        return 1;
    }

    if (cmd == "encrypt") {
        return cmd_encrypt(tray_path, target_path, kdf_alg, cipher_alg);
    } else {
        return cmd_decrypt(tray_path, target_path);
    }
}
