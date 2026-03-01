#include "tray.hpp"
#include "yaml_io.hpp"
#include "tray_pack.hpp"
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>

// ── Usage ─────────────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " keygen\n"
        "              --alias <name>\n"
        "              [--tray <level0|level1|level2-25519|level2|level3|level5>]\n"
        "              [--out <file>]\n"
        "              [--public]\n"
        "\n"
        "  --alias       Name for this tray (required)\n"
        "  --tray        Tray profile (default: level2-25519)\n"
        "  --out <file>  Write binary msgpack (.tray) to file; prints summary to stdout\n"
        "  --public      Also emit a companion public tray (no secret keys)\n"
        "\n"
        "Tray profiles:\n"
        "  level0       X25519 + Ed25519                           (classical-only)\n"
        "  level1       Kyber512 + Dilithium2                      (PQ-only)\n"
        "  level2-25519 X25519 + Kyber512 + Ed25519 + Dilithium2  (default)\n"
        "  level2       P-256  + Kyber512 + ECDSA P-256 + Dilithium2\n"
        "  level3       P-384  + Kyber768 + ECDSA P-384 + Dilithium3\n"
        "  level5       P-521  + Kyber1024 + ECDSA P-521 + Dilithium5\n"
        "\n"
        "Output (no --out): YAML to stdout. With --out: binary msgpack + summary to stdout.\n"
        "With --public: companion public tray (alias <name>.pub) also emitted.\n";
}

// ── Helpers ───────────────────────────────────────────────────────────────────

static void print_summary(const Tray& tray) {
    std::cout << "Tray generated:\n"
              << "  alias:   " << tray.alias         << "\n"
              << "  profile: " << tray.type_str       << "\n"
              << "  id:      " << tray.id             << "\n"
              << "  created: " << tray.created      << "\n"
              << "  expires: " << tray.expires      << "\n"
              << "  slots:   " << tray.slots.size() << "\n";
    for (const auto& s : tray.slots) {
        std::cout << "    - " << s.alg_name
                  << "  pk=" << s.pk.size() << "B"
                  << "  sk=" << s.sk.size() << "B\n";
    }
}

// Insert ".pub" before the last extension, e.g. "alice.tray" → "alice.pub.tray".
// Falls back to path + ".pub" if no extension found.
static std::string derive_pub_filename(const std::string& path) {
    auto dot = path.rfind('.');
    if (dot == std::string::npos)
        return path + ".pub";
    return path.substr(0, dot) + ".pub" + path.substr(dot);
}

// ── keygen command ────────────────────────────────────────────────────────────

static int cmd_keygen(int argc, char* argv[]) {
    std::string alias;
    std::string tray_str = "level2-25519";
    std::string out_file;
    bool pub_flag = false;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--alias") == 0) {
            if (++i >= argc) { std::cerr << "Error: --alias requires a value\n"; return 1; }
            alias = argv[i];
        } else if (std::strcmp(argv[i], "--tray") == 0) {
            if (++i >= argc) { std::cerr << "Error: --tray requires a value\n"; return 1; }
            tray_str = argv[i];
        } else if (std::strcmp(argv[i], "--out") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out requires a filename\n"; return 1; }
            out_file = argv[i];
        } else if (std::strcmp(argv[i], "--public") == 0) {
            pub_flag = true;
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n";
            return 1;
        }
    }

    if (alias.empty()) {
        std::cerr << "Error: --alias is required\n";
        return 1;
    }

    TrayType ttype;
    if      (tray_str == "level0")       ttype = TrayType::Level0;
    else if (tray_str == "level1")       ttype = TrayType::Level1;
    else if (tray_str == "level2-25519") ttype = TrayType::Level2_25519;
    else if (tray_str == "level2")       ttype = TrayType::Level2;
    else if (tray_str == "level3")       ttype = TrayType::Level3;
    else if (tray_str == "level5")       ttype = TrayType::Level5;
    else {
        std::cerr << "Error: unknown tray profile '" << tray_str
                  << "' (must be level0, level1, level2-25519, level2, level3, or level5)\n";
        return 1;
    }

    Tray tray;
    try {
        tray = make_tray(ttype, alias);
    } catch (const std::exception& e) {
        std::cerr << "Error: crypto failure: " << e.what() << "\n";
        return 2;
    }

    Tray pub_tray;
    if (pub_flag) {
        try {
            pub_tray = make_public_tray(tray);
        } catch (const std::exception& e) {
            std::cerr << "Error: public tray generation failed: " << e.what() << "\n";
            return 2;
        }
    }

    if (!out_file.empty()) {
        try {
            tray_mp::pack_to_file(tray, out_file);
        } catch (const std::exception& e) {
            std::cerr << "Error: msgpack write failed: " << e.what() << "\n";
            return 3;
        }
        if (pub_flag) {
            try {
                tray_mp::pack_to_file(pub_tray, derive_pub_filename(out_file));
            } catch (const std::exception& e) {
                std::cerr << "Error: public tray write failed: " << e.what() << "\n";
                return 3;
            }
        }
        // auto-summary to stdout
        print_summary(tray);
        if (pub_flag) print_summary(pub_tray);
    } else {
        try {
            std::cout << emit_tray_yaml(tray);
        } catch (const std::exception& e) {
            std::cerr << "Error: YAML output failed: " << e.what() << "\n";
            return 3;
        }
        if (pub_flag) {
            try {
                std::cout << emit_tray_yaml(pub_tray);
            } catch (const std::exception& e) {
                std::cerr << "Error: YAML output failed: " << e.what() << "\n";
                return 3;
            }
        }
    }

    return 0;
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "keygen") {
        return cmd_keygen(argc - 1, argv + 1);
    }

    if (cmd == "--help" || cmd == "-h") {
        print_usage(argv[0]);
        return 0;
    }

    std::cerr << "Error: unknown command '" << cmd << "'\n";
    print_usage(argv[0]);
    return 1;
}
