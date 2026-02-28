#include "tray_reader.hpp"
#include "kyber_kem.hpp"
#include "ec_kem.hpp"
#include "ec_sig.hpp"
#include "dilithium_sig.hpp"
#include "kdf.hpp"
#include "symmetric.hpp"
#include "armor.hpp"
#include "hyke_format.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <openssl/rand.h>

// ── Usage ─────────────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    std::cerr <<
        "Usage:\n"
        "  " << prog << " encrypt --tray <file> [--kdf SHAKE|KMAC] [--cipher AES-256-GCM|ChaCha20] <target-file>\n"
        "  " << prog << " decrypt --tray <file> <target-file>\n"
        "  " << prog << " sign    --tray <file> <target-file>\n"
        "  " << prog << " verify  --tray <file> <target-file>\n"
        "\n"
        "  --tray   Tray file (YAML or msgpack, auto-detected)\n"
        "  --kdf    Key derivation function (encrypt only): SHAKE (default) or KMAC\n"
        "  --cipher Symmetric cipher (encrypt only): AES-256-GCM (default) or ChaCha20\n"
        "\n"
        "  encrypt: reads <target-file>, writes OBIWAN armored ciphertext to stdout\n"
        "  decrypt: reads armored <target-file>, writes plaintext to stdout\n"
        "  sign:    encrypt-and-sign using all 4 tray slots; writes HYKE armor to stdout\n"
        "  verify:  verify both signatures and decrypt HYKE file; writes plaintext to stdout\n"
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

// Find the first classical signature slot (Ed25519 or ECDSA P-*)
static const Slot* find_classical_sig_slot(const Tray& tray) {
    for (const auto& s : tray.slots) {
        if (ec_sig::is_classical_sig(s.alg_name))
            return &s;
    }
    return nullptr;
}

// Find the first PQ signature slot (Dilithium*)
static const Slot* find_pq_sig_slot(const Tray& tray) {
    for (const auto& s : tray.slots) {
        if (dilithium_sig::is_pq_sig(s.alg_name))
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

// ── sign command ──────────────────────────────────────────────────────────────

static int cmd_sign(const std::string& tray_path,
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

    const Slot* cl_kem = find_classical_slot(tray);
    const Slot* pq_kem = find_pq_slot(tray);
    const Slot* cl_sig = find_classical_sig_slot(tray);
    const Slot* pq_sig = find_pq_sig_slot(tray);

    if (!cl_kem || !pq_kem || !cl_sig || !pq_sig) {
        std::cerr << "Error: tray must contain all 4 slots (KEM-classical, KEM-PQ, Sig-classical, Sig-PQ) for sign\n";
        return 1;
    }
    if (cl_sig->sk.empty() || pq_sig->sk.empty()) {
        std::cerr << "Error: tray signing secret keys (Sig-classical and Sig-PQ) are required for sign\n";
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
        ec_kem::encaps(cl_kem->alg_name, cl_kem->pk, ct_classical, ss_classical);
    } catch (const std::exception& e) {
        std::cerr << "Error: classical KEM encaps failed: " << e.what() << "\n";
        return 2;
    }

    // PQ KEM encaps
    std::vector<uint8_t> ct_pq, ss_pq;
    try {
        int kyber_level = kyber_kem::level_from_alg(pq_kem->alg_name);
        kyber_kem::encaps(kyber_level, pq_kem->pk, ct_pq, ss_pq);
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ KEM encaps failed: " << e.what() << "\n";
        return 2;
    }

    // Generate 32-byte random salt
    uint8_t salt[32];
    if (RAND_bytes(salt, 32) != 1) {
        std::cerr << "Error: RAND_bytes failed\n";
        return 2;
    }

    // HYKE KMAC KDF → symmetric key
    std::array<uint8_t, 32> sym_key;
    try {
        sym_key = derive_key_hyke(ss_classical, ss_pq, ct_classical, ct_pq, salt);
    } catch (const std::exception& e) {
        std::cerr << "Error: HYKE KDF failed: " << e.what() << "\n";
        return 2;
    }

    // AES-256-GCM encrypt
    std::vector<uint8_t> encrypted_payload;
    try {
        encrypted_payload = aes256gcm_encrypt(sym_key.data(), plaintext);
    } catch (const std::exception& e) {
        std::cerr << "Error: encryption failed: " << e.what() << "\n";
        return 2;
    }

    // Build HykeHeader (CTs populated; sigs filled in later)
    HykeHeader hdr;
    hdr.tray_id = tray_id_byte(tray.tray_type);
    try {
        parse_uuid(tray.id, hdr.tray_uuid);
    } catch (const std::exception& e) {
        std::cerr << "Error: failed to parse tray UUID: " << e.what() << "\n";
        return 2;
    }
    std::memcpy(hdr.salt, salt, 32);
    hdr.ct_classical = std::move(ct_classical);
    hdr.ct_pq        = std::move(ct_pq);

    // Pre-compute expected signature sizes (fixed by tray type / algorithm)
    uint32_t sig_cl_size = 0;
    int dilithium_mode   = 0;
    uint32_t sig_pq_size = 0;
    try {
        sig_cl_size    = (uint32_t)ec_sig::sig_bytes(cl_sig->alg_name);
        dilithium_mode = dilithium_sig::mode_from_alg(pq_sig->alg_name);
        sig_pq_size    = (uint32_t)dilithium_sig::sig_bytes_for_mode(dilithium_mode);
    } catch (const std::exception& e) {
        std::cerr << "Error: signature size lookup failed: " << e.what() << "\n";
        return 2;
    }

    // Build partial header (includes sig length fields but not the sig bytes themselves)
    auto partial_hdr = hyke_partial_header(hdr,
                                           (uint32_t)encrypted_payload.size(),
                                           sig_cl_size,
                                           sig_pq_size);

    // Compute context binding: ctx = KMAC256(key=pk_cl, msg=pk_pq || domain, outlen=512 bits)
    std::vector<uint8_t> ctx_bytes;
    try {
        ctx_bytes = compute_hyke_ctx(cl_kem->pk, pq_kem->pk);
    } catch (const std::exception& e) {
        std::cerr << "Error: context binding failed: " << e.what() << "\n";
        return 2;
    }

    // Build m_to_sign = ctx || partial_header || encrypted_payload
    std::vector<uint8_t> m_to_sign;
    m_to_sign.reserve(ctx_bytes.size() + partial_hdr.size() + encrypted_payload.size());
    m_to_sign.insert(m_to_sign.end(), ctx_bytes.begin(),     ctx_bytes.end());
    m_to_sign.insert(m_to_sign.end(), partial_hdr.begin(),   partial_hdr.end());
    m_to_sign.insert(m_to_sign.end(), encrypted_payload.begin(), encrypted_payload.end());

    // Classical signature
    try {
        ec_sig::sign(cl_sig->alg_name, cl_sig->sk, m_to_sign, hdr.sig_classical);
    } catch (const std::exception& e) {
        std::cerr << "Error: classical signing failed: " << e.what() << "\n";
        return 2;
    }

    // PQ (Dilithium) signature
    try {
        dilithium_sig::sign(dilithium_mode, pq_sig->sk, m_to_sign, hdr.sig_pq);
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ signing failed: " << e.what() << "\n";
        return 2;
    }

    // Pack and armor
    auto wire = hyke_pack(hdr, encrypted_payload);
    std::cout << hyke_armor(wire);
    return 0;
}

// ── verify command ────────────────────────────────────────────────────────────

static int cmd_verify(const std::string& tray_path,
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

    const Slot* cl_kem = find_classical_slot(tray);
    const Slot* pq_kem = find_pq_slot(tray);
    const Slot* cl_sig = find_classical_sig_slot(tray);
    const Slot* pq_sig = find_pq_sig_slot(tray);

    if (!cl_kem || !pq_kem || !cl_sig || !pq_sig) {
        std::cerr << "Error: tray must contain all 4 slots for verify\n";
        return 1;
    }
    if (cl_kem->sk.empty() || pq_kem->sk.empty()) {
        std::cerr << "Error: tray KEM secret keys (KEM-classical and KEM-PQ) are required for verify\n";
        return 1;
    }

    // Read armored file
    std::string armored;
    try {
        armored = read_file_text(target_path);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }

    // Dearmor and unpack
    std::vector<uint8_t> payload;
    HykeHeader hdr;
    try {
        auto wire = hyke_dearmor(armored);
        hdr = hyke_unpack(wire, payload);
    } catch (const std::exception& e) {
        std::cerr << "Error: failed to parse HYKE file: " << e.what() << "\n";
        return 3;
    }

    // Check tray_id matches
    if (hdr.tray_id != tray_id_byte(tray.tray_type)) {
        std::cerr << "Error: tray type mismatch (file was signed with a different tray type)\n";
        return 2;
    }

    // Reconstruct partial header (the bytes that were signed)
    auto partial_hdr = hyke_partial_header(hdr,
                                           (uint32_t)payload.size(),
                                           (uint32_t)hdr.sig_classical.size(),
                                           (uint32_t)hdr.sig_pq.size());

    // Compute context binding
    std::vector<uint8_t> ctx_bytes;
    try {
        ctx_bytes = compute_hyke_ctx(cl_kem->pk, pq_kem->pk);
    } catch (const std::exception& e) {
        std::cerr << "Error: context binding failed: " << e.what() << "\n";
        return 2;
    }

    // Build m_to_sign = ctx || partial_header || payload
    std::vector<uint8_t> m_to_sign;
    m_to_sign.reserve(ctx_bytes.size() + partial_hdr.size() + payload.size());
    m_to_sign.insert(m_to_sign.end(), ctx_bytes.begin(),   ctx_bytes.end());
    m_to_sign.insert(m_to_sign.end(), partial_hdr.begin(), partial_hdr.end());
    m_to_sign.insert(m_to_sign.end(), payload.begin(),     payload.end());

    // Verify classical signature
    try {
        if (!ec_sig::verify(cl_sig->alg_name, cl_sig->pk, m_to_sign, hdr.sig_classical)) {
            std::cerr << "Error: classical signature INVALID\n";
            return 2;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: classical signature verification failed: " << e.what() << "\n";
        return 2;
    }

    // Verify PQ (Dilithium) signature
    int dilithium_mode = 0;
    try {
        dilithium_mode = dilithium_sig::mode_from_alg(pq_sig->alg_name);
        if (!dilithium_sig::verify(dilithium_mode, pq_sig->pk, m_to_sign, hdr.sig_pq)) {
            std::cerr << "Error: PQ signature INVALID\n";
            return 2;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ signature verification failed: " << e.what() << "\n";
        return 2;
    }

    // Classical KEM decaps
    std::vector<uint8_t> ss_classical;
    try {
        ec_kem::decaps(cl_kem->alg_name, cl_kem->sk, hdr.ct_classical, ss_classical);
    } catch (const std::exception& e) {
        std::cerr << "Error: classical KEM decaps failed: " << e.what() << "\n";
        return 2;
    }

    // PQ KEM decaps
    std::vector<uint8_t> ss_pq;
    try {
        int kyber_level = kyber_kem::level_from_alg(pq_kem->alg_name);
        kyber_kem::decaps(kyber_level, pq_kem->sk, hdr.ct_pq, ss_pq);
    } catch (const std::exception& e) {
        std::cerr << "Error: PQ KEM decaps failed: " << e.what() << "\n";
        return 2;
    }

    // HYKE KMAC KDF
    std::array<uint8_t, 32> sym_key;
    try {
        sym_key = derive_key_hyke(ss_classical, ss_pq, hdr.ct_classical, hdr.ct_pq, hdr.salt);
    } catch (const std::exception& e) {
        std::cerr << "Error: HYKE KDF failed: " << e.what() << "\n";
        return 2;
    }

    // AES-256-GCM decrypt
    std::vector<uint8_t> plaintext;
    try {
        plaintext = aes256gcm_decrypt(sym_key.data(), payload);
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

    if (cmd != "encrypt" && cmd != "decrypt" && cmd != "sign" && cmd != "verify") {
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
    } else if (cmd == "decrypt") {
        return cmd_decrypt(tray_path, target_path);
    } else if (cmd == "sign") {
        return cmd_sign(tray_path, target_path);
    } else {
        return cmd_verify(tray_path, target_path);
    }
}
