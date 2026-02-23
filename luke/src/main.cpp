#include "kyber_api.hpp"
#include "kyber_ops.hpp"
#include "pem_io.hpp"
#include <iostream>
#include <string>
#include <map>
#include <cstdlib>

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
        "\n"
        "Options:\n"
        "  --level <512|768|1024>   Security level (default: 768)\n"
        "  --impl  <ref|avx2>       Implementation (default: ref)\n"
        "  --pk    <file>           Public key file\n"
        "  --sk    <file>           Secret key file\n"
        "  --kem   <file>           Encapsulated key\n"
        "  --ss    <file>           base64-encoded 256 bit secret key\n"
        "\n"
        "Examples:\n"
        "  " << prog << " keygen --pk alice.pk --sk alice.sk\n"
        "  " << prog << " encaps --pk alice.pk --kem kem.ct --ss secret.ss\n"
        "  " << prog << " decaps --sk alice.sk --kem kem.ct --ss secret.ss\n"
        "  " << prog << " keygen --level 1024 --impl avx2 --pk alice.pk --sk alice.sk\n";
}

// ── Argument parser ───────────────────────────────────────────────────────────
struct Args {
    std::string command;
    int         level = 768;
    bool        avx2  = false;
    std::string pk, sk, ct, ss;
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
        args.command != "decaps") {
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
        kyber::keygen(params, pk, sk);
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
        kyber::encaps(params, pk, ct, ss);
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

// ── main ──────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args, argv[0]))
        return EXIT_USAGE;

    if (args.command == "keygen") return cmd_keygen(args);
    if (args.command == "encaps") return cmd_encaps(args);
    if (args.command == "decaps") return cmd_decaps(args);

    // Should be unreachable
    return EXIT_USAGE;
}
