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
        "              [--tray <level2|level2nist|level3nist|level5nist>]\n"
        "              [--summary]\n"
        "              [--classiconly | --pqonly]\n"
        "\n"
        "  --tray        Tray type (default: level2)\n"
        "  --alias       Name for this tray (required)\n"
        "  --summary     Print a human-readable summary instead of YAML\n"
        "  --out <file>  Write binary msgpack (.tray) to file instead of YAML stdout\n"
        "  --classiconly Include only classical (EC/EdDSA) key slots\n"
        "  --pqonly      Include only post-quantum (Kyber/Dilithium) key slots\n"
        "\n"
        "Output: YAML tray to stdout (default). Use --out to write binary msgpack.\n"
        "\n"
        "Tray types:\n"
        "  level2      X25519 + Kyber-512 + Ed25519 + Dilithium2\n"
        "  level2nist  P-256  + Kyber-512 + ECDSA P-256 + Dilithium2\n"
        "  level3nist  P-384  + Kyber-768 + ECDSA P-384 + Dilithium3\n"
        "  level5nist  P-521  + Kyber-1024 + ECDSA P-521 + Dilithium5\n";
}

// ── keygen command ────────────────────────────────────────────────────────────

static int cmd_keygen(int argc, char* argv[]) {
    std::string alias;
    std::string tray_str = "level2";
    std::string out_file;
    bool summary_only = false;
    bool classic_only = false;
    bool pq_only      = false;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--alias") == 0) {
            if (++i >= argc) { std::cerr << "Error: --alias requires a value\n"; return 1; }
            alias = argv[i];
        } else if (std::strcmp(argv[i], "--tray") == 0) {
            if (++i >= argc) { std::cerr << "Error: --tray requires a value\n"; return 1; }
            tray_str = argv[i];
        } else if (std::strcmp(argv[i], "--summary") == 0) {
            summary_only = true;
        } else if (std::strcmp(argv[i], "--out") == 0) {
            if (++i >= argc) { std::cerr << "Error: --out requires a filename\n"; return 1; }
            out_file = argv[i];
        } else if (std::strcmp(argv[i], "--yaml") == 0) {
            // accepted for backwards compatibility; YAML is already the default
        } else if (std::strcmp(argv[i], "--classiconly") == 0) {
            classic_only = true;
        } else if (std::strcmp(argv[i], "--pqonly") == 0) {
            pq_only = true;
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n";
            return 1;
        }
    }

    // Validate
    if (alias.empty()) {
        std::cerr << "Error: --alias is required\n";
        return 1;
    }
    if (classic_only && pq_only) {
        std::cerr << "Error: --classiconly and --pqonly are mutually exclusive\n";
        return 1;
    }

    TrayType ttype;
    if      (tray_str == "level2")     ttype = TrayType::Level2;
    else if (tray_str == "level2nist") ttype = TrayType::Level2NIST;
    else if (tray_str == "level3nist") ttype = TrayType::Level3NIST;
    else if (tray_str == "level5nist") ttype = TrayType::Level5NIST;
    else {
        std::cerr << "Error: unknown tray type '" << tray_str
                  << "' (must be level2, level2nist, level3nist, or level5nist)\n";
        return 1;
    }

    Tray tray;
    try {
        tray = make_tray(ttype, alias, classic_only, pq_only);
    } catch (const std::exception& e) {
        std::cerr << "Error: crypto failure: " << e.what() << "\n";
        return 2;
    }

    if (!out_file.empty()) {
        try {
            tray_mp::pack_to_file(tray, out_file);
        } catch (const std::exception& e) {
            std::cerr << "Error: msgpack write failed: " << e.what() << "\n";
            return 3;
        }
    } else if (summary_only) {
        std::cout << "Tray generated:\n"
                  << "  alias:   " << tray.alias       << "\n"
                  << "  type:    " << tray.type_str     << "\n"
                  << "  id:      " << tray.id           << "\n"
                  << "  created: " << tray.created      << "\n"
                  << "  expires: " << tray.expires      << "\n"
                  << "  slots:   " << tray.slots.size() << "\n";
        for (const auto& s : tray.slots) {
            std::cout << "    - " << s.alg_name
                      << "  pk=" << s.pk.size() << "B"
                      << "  sk=" << s.sk.size() << "B\n";
        }
    } else {
        try {
            std::cout << emit_tray_yaml(tray);
        } catch (const std::exception& e) {
            std::cerr << "Error: YAML output failed: " << e.what() << "\n";
            return 3;
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
