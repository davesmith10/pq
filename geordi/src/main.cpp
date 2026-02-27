#include "dilithium_api.hpp"
#include "dilithium_ops.hpp"
#include "pem_io.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>

// ── Exit codes ────────────────────────────────────────────────────────────────
static const int EXIT_OK     = 0;
static const int EXIT_USAGE  = 1;
static const int EXIT_CRYPTO = 2;
static const int EXIT_IO     = 3;

// ── Default signing context ───────────────────────────────────────────────────
static const uint8_t kDefaultCtx[] = "geordi:signing:v1";
static const size_t  kDefaultCtxLen = sizeof(kDefaultCtx) - 1;

// ── Usage ─────────────────────────────────────────────────────────────────────
static void print_usage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " <command> [options]\n"
        "\n"
        "Commands:\n"
        "  keygen    Generate a Dilithium keypair\n"
        "  sign      Sign a message\n"
        "  verify    Verify a signature\n"
        "\n"
        "Options:\n"
        "  --d2              Security level ML-DSA-44 / Dilithium2\n"
        "  --d3              Security level ML-DSA-65 / Dilithium3 (default)\n"
        "  --d5              Security level ML-DSA-87 / Dilithium5\n"
        "  --impl <ref|avx2> Implementation (default: ref)\n"
        "  --pk   <file>     Public key file\n"
        "  --sk   <file>     Secret key file\n"
        "  --msg  <file>     Message file\n"
        "  --sig  <file>     Signature file\n"
        "  --ctx  <string>   Signing context (default: \"geordi:signing:v1\")\n"
        "\n"
        "Examples:\n"
        "  " << prog << " keygen --pk alice.pub --sk alice.priv\n"
        "  " << prog << " sign   --sk alice.priv --msg msg.txt --sig msg.sig\n"
        "  " << prog << " verify --pk alice.pub  --msg msg.txt --sig msg.sig\n"
        "  " << prog << " keygen --d5 --impl avx2 --pk alice.pub --sk alice.priv\n";
}

// ── Argument parser ───────────────────────────────────────────────────────────
struct Args {
    std::string command;
    int         mode = 3;    // 2, 3, or 5
    bool        avx2 = false;
    std::string pk, sk, msg, sig;
    std::string ctx;
    bool        has_ctx = false;
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
        args.command != "sign"   &&
        args.command != "verify") {
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

        if (opt == "--d2") {
            args.mode = 2;
        } else if (opt == "--d3") {
            args.mode = 3;
        } else if (opt == "--d5") {
            args.mode = 5;
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
        } else if (opt == "--msg") {
            if (!need_val()) return false;
            args.msg = argv[++i];
        } else if (opt == "--sig") {
            if (!need_val()) return false;
            args.sig = argv[++i];
        } else if (opt == "--ctx") {
            if (!need_val()) return false;
            args.ctx = argv[++i];
            args.has_ctx = true;
        } else {
            std::cerr << "Unknown option: " << opt << "\n\n";
            print_usage(prog);
            return false;
        }
    }
    return true;
}

// ── Read a binary file into a vector ─────────────────────────────────────────
static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot open file for reading: " + path);
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f),
        std::istreambuf_iterator<char>());
}

// ── Commands ──────────────────────────────────────────────────────────────────
static int cmd_keygen(const Args& args) {
    if (args.pk.empty() || args.sk.empty()) {
        std::cerr << "keygen requires --pk and --sk\n";
        return EXIT_USAGE;
    }

    DilithiumParams params = make_params(args.mode, args.avx2);
    std::vector<uint8_t> pk, sk;

    try {
        dilithium::keygen(params, pk, sk);
    } catch (const std::exception& e) {
        std::cerr << "Crypto error: " << e.what() << "\n";
        return EXIT_CRYPTO;
    }

    try {
        write_pem(args.pk, params.label + " PUBLIC KEY", pk);
        write_pem(args.sk, params.label + " SECRET KEY", sk);
    } catch (const std::exception& e) {
        std::cerr << "I/O error: " << e.what() << "\n";
        return EXIT_IO;
    }

    std::cout << "Generated " << params.label << " keypair\n"
              << "  Public key: " << args.pk << " (" << pk.size() << " bytes)\n"
              << "  Secret key: " << args.sk << " (" << sk.size() << " bytes)\n";
    return EXIT_OK;
}

static int cmd_sign(const Args& args) {
    if (args.sk.empty() || args.msg.empty()) {
        std::cerr << "sign requires --sk and --msg\n";
        return EXIT_USAGE;
    }

    DilithiumParams params = make_params(args.mode, args.avx2);

    std::vector<uint8_t> sk, msg;
    try {
        sk  = read_pem(args.sk, params.label + " SECRET KEY");
        msg = read_file(args.msg);
    } catch (const std::exception& e) {
        std::cerr << "I/O error: " << e.what() << "\n";
        return EXIT_IO;
    }

    const uint8_t* ctx_ptr;
    size_t         ctx_len;
    std::vector<uint8_t> ctx_buf;
    if (args.has_ctx) {
        ctx_buf.assign(args.ctx.begin(), args.ctx.end());
        ctx_ptr = ctx_buf.data();
        ctx_len = ctx_buf.size();
    } else {
        ctx_ptr = kDefaultCtx;
        ctx_len = kDefaultCtxLen;
    }

    std::vector<uint8_t> sig;
    try {
        dilithium::sign(params, sk, msg, ctx_ptr, ctx_len, sig);
    } catch (const std::exception& e) {
        std::cerr << "Crypto error: " << e.what() << "\n";
        return EXIT_CRYPTO;
    }

    try {
        if (args.sig.empty()) {
            write_pem(std::cout, params.label + " SIGNATURE", sig);
        } else {
            write_pem(args.sig, params.label + " SIGNATURE", sig);
            std::cout << "Signed message\n"
                      << "  Signature: " << args.sig << " (" << sig.size() << " bytes)\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "I/O error: " << e.what() << "\n";
        return EXIT_IO;
    }
    return EXIT_OK;
}

static int cmd_verify(const Args& args) {
    if (args.pk.empty() || args.msg.empty() || args.sig.empty()) {
        std::cerr << "verify requires --pk, --msg, and --sig\n";
        return EXIT_USAGE;
    }

    DilithiumParams params = make_params(args.mode, args.avx2);

    std::vector<uint8_t> pk, msg, sig;
    try {
        pk  = read_pem(args.pk,  params.label + " PUBLIC KEY");
        msg = read_file(args.msg);
        sig = read_pem(args.sig, params.label + " SIGNATURE");
    } catch (const std::exception& e) {
        std::cerr << "I/O error: " << e.what() << "\n";
        return EXIT_IO;
    }

    const uint8_t* ctx_ptr;
    size_t         ctx_len;
    std::vector<uint8_t> ctx_buf;
    if (args.has_ctx) {
        ctx_buf.assign(args.ctx.begin(), args.ctx.end());
        ctx_ptr = ctx_buf.data();
        ctx_len = ctx_buf.size();
    } else {
        ctx_ptr = kDefaultCtx;
        ctx_len = kDefaultCtxLen;
    }

    bool valid = false;
    try {
        valid = dilithium::verify(params, pk, msg, ctx_ptr, ctx_len, sig);
    } catch (const std::exception& e) {
        std::cerr << "Crypto error: " << e.what() << "\n";
        return EXIT_CRYPTO;
    }

    if (valid) {
        std::cout << "Signature valid.\n";
        return EXIT_OK;
    } else {
        std::cout << "Signature INVALID.\n";
        return EXIT_CRYPTO;
    }
}

// ── main ──────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args, argv[0]))
        return EXIT_USAGE;

    if (args.command == "keygen") return cmd_keygen(args);
    if (args.command == "sign")   return cmd_sign(args);
    if (args.command == "verify") return cmd_verify(args);

    // Should be unreachable
    return EXIT_USAGE;
}
