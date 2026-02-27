#include "kyber_api.hpp"
#include "kyber_ops.hpp"
#include "pem_io.hpp"
#include "base64.hpp"
#include "aes_gcm.hpp"
#include "bundle.hpp"
#include "password.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <cstdlib>
#include <openssl/rand.h>

// ── Exit codes ────────────────────────────────────────────────────────────────
static const int EXIT_OK      = 0;
static const int EXIT_USAGE   = 1;
static const int EXIT_CRYPTO  = 2;
static const int EXIT_IO      = 3;

// ── Usage ─────────────────────────────────────────────────────────────────────
static void print_usage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " <command> [options]\n"
        "\n"
        "Commands:\n"
        "  keygen    Generate a Kyber keypair\n"
        "  encaps    Encapsulate a shared secret using a public key\n"
        "  decaps    Decapsulate a ciphertext using a secret key\n"
        "  encrypt   Encrypt a file (Kyber KEM + AES-256-GCM)\n"
        "  decrypt   Decrypt a .lukb bundle file\n"
        "\n"
        "Options:\n"
        "  --level <512|768|1024>   Security level (default: 768)\n"
        "  --impl  <ref|avx2>       Implementation (default: ref)\n"
        "  --pk    <file>           Public key file\n"
        "  --sk    <file>           Secret key file\n"
        "  --kem   <file>           Encapsulated key\n"
        "  --ss      <file>           base64-encoded 256 bit secret key\n"
        "  --seed    <base64>         32-byte (256-bit) seed for deterministic keygen/encaps\n"
        "  --in      <file>           Input plaintext or bundle file\n"
        "  --out     <file>           Output bundle or plaintext file (default: stdout)\n"
        "\n"
        "Examples:\n"
        "  " << prog << " keygen --pk alice.pk --sk alice.sk\n"
        "  " << prog << " encaps --pk alice.pk --kem kem.ct --ss secret.ss\n"
        "  " << prog << " decaps --sk alice.sk --kem kem.ct --ss secret.ss\n"
        "  " << prog << " keygen --level 1024 --impl avx2 --pk alice.pk --sk alice.sk\n"
        "  " << prog << " keygen --seed <base64-32-bytes> --pk alice.pk --sk alice.sk\n"
        "  " << prog << " encrypt --in plain.txt                      (prompts for passphrase)\n"
        "  " << prog << " encrypt --pk alice.pk --in plain.txt --out out.lukb\n"
        "  " << prog << " decrypt --in out.lukb                       (prompts for passphrase)\n"
        "  " << prog << " decrypt --sk alice.sk --in out.lukb --out plain.txt\n";
}

// ── Argument parser ───────────────────────────────────────────────────────────
struct Args {
    std::string command;
    int         level = 768;
    bool        avx2  = false;
    std::string pk, sk, ct, ss;
    std::string seed;   // base64-encoded 32-byte seed for deterministic ops (keygen/encaps only)
    std::string in_file, out_file;
};

static bool parse_args(int argc, char** argv, Args& args, const char* prog) {
    if (argc < 2) {
        print_usage(prog);
        return false;
    }
    args.command = argv[1];
    if (args.command == "--help" || args.command == "-h") {
        print_usage(prog);
        return false;
    }
    if (args.command != "keygen" &&
        args.command != "encaps" &&
        args.command != "decaps" &&
        args.command != "encrypt" &&
        args.command != "decrypt") {
        std::cerr << "Unknown command: " << args.command << "\n\n";
        print_usage(prog);
        return false;
    }

    for (int i = 2; i < argc; ++i) {
        std::string opt = argv[i];
        auto need_val = [&]() -> bool {
            if (i + 1 >= argc) {
                std::cerr << "Option " << opt << " requires a value\n";
                return false;
            }
            return true;
        };

        if (opt == "--level") {
            if (!need_val()) return false;
            args.level = std::atoi(argv[++i]);
            if (args.level != 512 && args.level != 768 && args.level != 1024) {
                std::cerr << "Invalid level: " << args.level
                          << " (must be 512, 768, or 1024)\n";
                return false;
            }
        } else if (opt == "--impl") {
            if (!need_val()) return false;
            std::string impl = argv[++i];
            if (impl == "avx2") {
                args.avx2 = true;
            } else if (impl == "ref") {
                args.avx2 = false;
            } else {
                std::cerr << "Invalid impl: " << impl << " (must be ref or avx2)\n";
                return false;
            }
        } else if (opt == "--pk") {
            if (!need_val()) return false;
            args.pk = argv[++i];
        } else if (opt == "--sk") {
            if (!need_val()) return false;
            args.sk = argv[++i];
        } else if (opt == "--kem") {
            if (!need_val()) return false;
            args.ct = argv[++i];
        } else if (opt == "--ss") {
            if (!need_val()) return false;
            args.ss = argv[++i];
        } else if (opt == "--seed") {
            if (!need_val()) return false;
            args.seed = argv[++i];
        } else if (opt == "--in") {
            if (!need_val()) return false;
            args.in_file = argv[++i];
        } else if (opt == "--out") {
            if (!need_val()) return false;
            args.out_file = argv[++i];
        } else {
            std::cerr << "Unknown option: " << opt << "\n\n";
            print_usage(prog);
            return false;
        }
    }
    return true;
}

// ── PEM type header helpers ───────────────────────────────────────────────────
static std::string level_tag(int level) {
    return "KYBER" + std::to_string(level);
}

// ── Commands ──────────────────────────────────────────────────────────────────
static int cmd_keygen(const Args& args) {
    if (args.pk.empty() || args.sk.empty()) {
        std::cerr << "keygen requires --pk and --sk\n";
        return EXIT_USAGE;
    }

    KyberParams params = make_params(args.level, args.avx2);
    std::vector<uint8_t> pk, sk;

    try {
        if (!args.seed.empty()) {
            std::vector<uint8_t> seed_bytes;
            try {
                seed_bytes = base64_decode(args.seed);
            } catch (const std::exception&) {
                std::cerr << "--seed: invalid base64\n";
                return EXIT_USAGE;
            }
            if (seed_bytes.size() != 32) {
                std::cerr << "--seed: must decode to exactly 32 bytes (got "
                          << seed_bytes.size() << ")\n";
                return EXIT_USAGE;
            }
            kyber::keygen_derand(params, seed_bytes.data(), pk, sk);
        } else {
            kyber::keygen(params, pk, sk);
        }
    } catch (const std::exception& e) {
        std::cerr << "Crypto error: " << e.what() << "\n";
        return EXIT_CRYPTO;
    }

    std::string tag = level_tag(args.level);
    try {
        write_pem(args.pk, tag + " PUBLIC KEY", pk);
        write_pem(args.sk, tag + " SECRET KEY", sk);
    } catch (const std::exception& e) {
        std::cerr << "I/O error: " << e.what() << "\n";
        return EXIT_IO;
    }

    std::cout << "Generated " << tag << " keypair\n"
              << "  Public key: " << args.pk << " (" << pk.size() << " bytes)\n"
              << "  Secret key: " << args.sk << " (" << sk.size() << " bytes)\n";
    return EXIT_OK;
}

static int cmd_encaps(const Args& args) {
    if (args.pk.empty() || args.ct.empty() || args.ss.empty()) {
        std::cerr << "encaps requires --pk, --kem, and --ss\n";
        return EXIT_USAGE;
    }

    KyberParams params = make_params(args.level, args.avx2);
    std::string tag = level_tag(args.level);

    std::vector<uint8_t> pk;
    try {
        pk = read_pem(args.pk, tag + " PUBLIC KEY");
    } catch (const std::exception& e) {
        std::cerr << "I/O error reading public key: " << e.what() << "\n";
        return EXIT_IO;
    }

    std::vector<uint8_t> ct, ss;
    try {
        if (!args.seed.empty()) {
            std::vector<uint8_t> seed_bytes;
            try {
                seed_bytes = base64_decode(args.seed);
            } catch (const std::exception&) {
                std::cerr << "--seed: invalid base64\n";
                return EXIT_USAGE;
            }
            if (seed_bytes.size() != 32) {
                std::cerr << "--seed: must decode to exactly 32 bytes (got "
                          << seed_bytes.size() << ")\n";
                return EXIT_USAGE;
            }
            kyber::encaps_derand(params, pk, seed_bytes.data(), ct, ss);
        } else {
            kyber::encaps(params, pk, ct, ss);
        }
    } catch (const std::exception& e) {
        std::cerr << "Crypto error: " << e.what() << "\n";
        return EXIT_CRYPTO;
    }

    try {
        write_pem(args.ct, tag + " CIPHERTEXT", ct);
        write_pem(args.ss, tag + " SHARED SECRET", ss);
    } catch (const std::exception& e) {
        std::cerr << "I/O error: " << e.what() << "\n";
        return EXIT_IO;
    }

    std::cout << "Encapsulated shared secret\n"
              << "  Ciphertext:    " << args.ct << " (" << ct.size() << " bytes)\n"
              << "  Shared secret: " << args.ss << " (" << ss.size() << " bytes)\n";
    return EXIT_OK;
}

static int cmd_decaps(const Args& args) {
    if (args.sk.empty() || args.ct.empty() || args.ss.empty()) {
        std::cerr << "decaps requires --sk, --kem, and --ss\n";
        return EXIT_USAGE;
    }

    KyberParams params = make_params(args.level, args.avx2);
    std::string tag = level_tag(args.level);

    std::vector<uint8_t> sk, ct;
    try {
        sk = read_pem(args.sk, tag + " SECRET KEY");
        ct = read_pem(args.ct, tag + " CIPHERTEXT");
    } catch (const std::exception& e) {
        std::cerr << "I/O error reading keys: " << e.what() << "\n";
        return EXIT_IO;
    }

    std::vector<uint8_t> ss;
    try {
        kyber::decaps(params, sk, ct, ss);
    } catch (const std::exception& e) {
        std::cerr << "Crypto error: " << e.what() << "\n";
        return EXIT_CRYPTO;
    }

    try {
        write_pem(args.ss, tag + " SHARED SECRET", ss);
    } catch (const std::exception& e) {
        std::cerr << "I/O error: " << e.what() << "\n";
        return EXIT_IO;
    }

    std::cout << "Decapsulated shared secret\n"
              << "  Shared secret: " << args.ss << " (" << ss.size() << " bytes)\n";
    return EXIT_OK;
}

static int cmd_encrypt(const Args& args) {
    if (args.in_file.empty()) {
        std::cerr << "encrypt requires --in\n";
        return EXIT_USAGE;
    }

    KyberParams params = make_params(args.level, args.avx2);
    std::string tag = level_tag(args.level);

    // Resolve public key and salt
    std::vector<uint8_t> pk;
    std::vector<uint8_t> salt(BUNDLE_SALT_LEN, 0);  // all-zeros for --pk mode

    if (!args.pk.empty()) {
        // Public-key mode: read pk file, salt stays all-zeros
        try { pk = read_pem(args.pk, tag + " PUBLIC KEY"); }
        catch (const std::exception& e) {
            std::cerr << "I/O error reading public key: " << e.what() << "\n"; return EXIT_IO;
        }
    } else {
        // Password mode: prompt, derive seed via PBKDF2, generate ephemeral keypair
        std::string passphrase = read_hidden("Enter passphrase: ");
        if (!validate_password(passphrase)) return EXIT_USAGE;

        if (RAND_bytes(salt.data(), static_cast<int>(BUNDLE_SALT_LEN)) != 1) {
            std::cerr << "Crypto error: RAND_bytes failed\n"; return EXIT_CRYPTO;
        }

        std::vector<uint8_t> seed;
        try { seed = pbkdf2_derive(passphrase, salt.data()); }
        catch (const std::exception& e) {
            std::cerr << "Crypto error: " << e.what() << "\n"; return EXIT_CRYPTO;
        }

        std::vector<uint8_t> sk_unused;
        try { kyber::keygen_derand(params, seed.data(), pk, sk_unused); }
        catch (const std::exception& e) {
            std::cerr << "Crypto error: " << e.what() << "\n"; return EXIT_CRYPTO;
        }
    }

    // KEM encapsulation
    std::vector<uint8_t> ct, ss;
    try { kyber::encaps(params, pk, ct, ss); }
    catch (const std::exception& e) {
        std::cerr << "Crypto error: " << e.what() << "\n"; return EXIT_CRYPTO;
    }

    // Read plaintext
    std::ifstream fin(args.in_file, std::ios::binary);
    if (!fin) {
        std::cerr << "I/O error: cannot open input file: " << args.in_file << "\n";
        return EXIT_IO;
    }
    std::vector<uint8_t> plaintext(
        (std::istreambuf_iterator<char>(fin)),
        std::istreambuf_iterator<char>()
    );

    // AES-256-GCM encrypt
    std::vector<uint8_t> nonce_tag_body;
    try { nonce_tag_body = aes256gcm_encrypt(ss.data(), plaintext); }
    catch (const std::exception& e) {
        std::cerr << "Crypto error: " << e.what() << "\n"; return EXIT_CRYPTO;
    }

    // Write bundle
    try {
        if (args.out_file.empty()) {
            bundle_write(std::cout, args.level, salt, ct, nonce_tag_body);
        } else {
            std::ofstream fout(args.out_file, std::ios::binary);
            if (!fout) {
                std::cerr << "I/O error: cannot open output file: " << args.out_file << "\n";
                return EXIT_IO;
            }
            bundle_write(fout, args.level, salt, ct, nonce_tag_body);
            std::cout << "Encrypted\n"
                      << "  Input:  " << args.in_file  << " (" << plaintext.size() << " bytes)\n"
                      << "  Output: " << args.out_file << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "I/O error: " << e.what() << "\n"; return EXIT_IO;
    }
    return EXIT_OK;
}

static int cmd_decrypt(const Args& args) {
    if (args.in_file.empty()) {
        std::cerr << "decrypt requires --in\n";
        return EXIT_USAGE;
    }

    // Open bundle (text mode — file contains a base64 line)
    std::ifstream fin(args.in_file);
    if (!fin) {
        std::cerr << "I/O error: cannot open bundle: " << args.in_file << "\n";
        return EXIT_IO;
    }

    BundleData bdata;
    try {
        bdata = bundle_read(fin);
    } catch (const std::exception& e) {
        std::cerr << "Bundle error: " << e.what() << "\n"; return EXIT_IO;
    }

    KyberParams params = make_params(bdata.level, args.avx2);
    std::string tag = level_tag(bdata.level);

    // Resolve secret key
    std::vector<uint8_t> sk;
    if (!args.sk.empty()) {
        // Secret-key mode: read sk file
        try { sk = read_pem(args.sk, tag + " SECRET KEY"); }
        catch (const std::exception& e) {
            std::cerr << "I/O error reading secret key: " << e.what() << "\n"; return EXIT_IO;
        }
    } else {
        // Password mode: prompt, re-derive seed from bundle salt, reconstruct sk
        std::string passphrase = read_hidden("Enter passphrase: ");
        if (!validate_password(passphrase)) return EXIT_USAGE;

        std::vector<uint8_t> seed;
        try { seed = pbkdf2_derive(passphrase, bdata.salt.data()); }
        catch (const std::exception& e) {
            std::cerr << "Crypto error: " << e.what() << "\n"; return EXIT_CRYPTO;
        }

        std::vector<uint8_t> pk_unused;
        try { kyber::keygen_derand(params, seed.data(), pk_unused, sk); }
        catch (const std::exception& e) {
            std::cerr << "Crypto error: " << e.what() << "\n"; return EXIT_CRYPTO;
        }
    }

    // KEM decapsulation
    std::vector<uint8_t> ss;
    try { kyber::decaps(params, sk, bdata.ct, ss); }
    catch (const std::exception& e) {
        std::cerr << "Crypto error: " << e.what() << "\n"; return EXIT_CRYPTO;
    }

    // AES-256-GCM decrypt
    std::vector<uint8_t> plaintext;
    try { plaintext = aes256gcm_decrypt(ss.data(), bdata.nonce_tag_body); }
    catch (const std::exception& e) {
        std::cerr << "Crypto error: " << e.what() << "\n"; return EXIT_CRYPTO;
    }

    // Write plaintext
    if (args.out_file.empty()) {
        std::cout.write(reinterpret_cast<const char*>(plaintext.data()),
                        static_cast<std::streamsize>(plaintext.size()));
        std::cout << '\n';
    } else {
        std::ofstream fout(args.out_file, std::ios::binary);
        if (!fout) {
            std::cerr << "I/O error: cannot open output file: " << args.out_file << "\n";
            return EXIT_IO;
        }
        fout.write(reinterpret_cast<const char*>(plaintext.data()),
                   static_cast<std::streamsize>(plaintext.size()));
        if (!fout) {
            std::cerr << "I/O error writing output\n"; return EXIT_IO;
        }
        std::cout << "Decrypted\n"
                  << "  Input:  " << args.in_file  << "\n"
                  << "  Output: " << args.out_file << " (" << plaintext.size() << " bytes)\n";
    }
    return EXIT_OK;
}

// ── main ──────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args, argv[0]))
        return EXIT_USAGE;

    if (args.command == "keygen")  return cmd_keygen(args);
    if (args.command == "encaps")  return cmd_encaps(args);
    if (args.command == "decaps")  return cmd_decaps(args);
    if (args.command == "encrypt") return cmd_encrypt(args);
    if (args.command == "decrypt") return cmd_decrypt(args);

    // Should be unreachable
    return EXIT_USAGE;
}
