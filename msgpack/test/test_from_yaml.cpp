#include "tray_pack.hpp"
#include "base64.hpp"
#include <yaml-cpp/yaml.h>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <sys/stat.h>

static TrayType type_str_to_enum(const std::string& s) {
    if (s == "level2")     return TrayType::Level2;
    if (s == "level2nist") return TrayType::Level2NIST;
    if (s == "level3nist") return TrayType::Level3NIST;
    if (s == "level5nist") return TrayType::Level5NIST;
    throw std::runtime_error("Unknown tray type: " + s);
}

static off_t file_size(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return -1;
    return st.st_size;
}

static bool fail(const std::string& msg) {
    std::cerr << "FAIL: " << msg << "\n";
    return false;
}

int main(int argc, char* argv[]) {
    std::string path = "../../data/alice.tray";
    if (argc > 1) path = argv[1];

    // Parse YAML
    YAML::Node doc;
    try {
        doc = YAML::LoadFile(path);
    } catch (const std::exception& e) {
        std::cerr << "Cannot load YAML: " << e.what() << "\n";
        return 1;
    }

    // Build Tray from YAML
    Tray t;
    try {
        t.version  = doc["version"].as<int>();
        t.alias    = doc["alias"].as<std::string>();
        t.type_str = doc["type"].as<std::string>();
        t.tray_type = type_str_to_enum(t.type_str);
        t.id       = doc["id"].as<std::string>();
        t.created  = doc["created"].as<std::string>();
        t.expires  = doc["expires"].as<std::string>();

        for (const auto& sn : doc["tray"]) {
            Slot s;
            s.alg_name = sn["alg"].as<std::string>();
            s.pk = base64_decode(sn["pk"].as<std::string>());
            if (sn["sk"]) {
                s.sk = base64_decode(sn["sk"].as<std::string>());
            }
            t.slots.push_back(std::move(s));
        }
    } catch (const std::exception& e) {
        std::cerr << "YAML parse error: " << e.what() << "\n";
        return 1;
    }

    // Pack → Unpack round-trip
    std::vector<uint8_t> packed;
    Tray u;
    try {
        packed = tray_mp::pack(t);
        u = tray_mp::unpack(packed);
    } catch (const std::exception& e) {
        std::cerr << "FAIL: pack/unpack threw: " << e.what() << "\n";
        return 1;
    }

    // Compare
    bool ok = true;
    if (u.version   != t.version)   ok = fail("version mismatch");
    if (u.alias     != t.alias)     ok = fail("alias mismatch");
    if (u.type_str  != t.type_str)  ok = fail("type_str mismatch");
    if (u.tray_type != t.tray_type) ok = fail("tray_type mismatch");
    if (u.id        != t.id)        ok = fail("id mismatch");
    if (u.created   != t.created)   ok = fail("created mismatch");
    if (u.expires   != t.expires)   ok = fail("expires mismatch");
    if (u.slots.size() != t.slots.size())
        ok = fail("slots.size() mismatch: got " + std::to_string(u.slots.size()) +
                  " expected " + std::to_string(t.slots.size()));

    for (size_t i = 0; i < t.slots.size() && i < u.slots.size(); ++i) {
        if (u.slots[i].alg_name != t.slots[i].alg_name)
            ok = fail("slot[" + std::to_string(i) + "] alg_name mismatch");
        if (u.slots[i].pk != t.slots[i].pk)
            ok = fail("slot[" + std::to_string(i) + "] pk mismatch (size orig=" +
                      std::to_string(t.slots[i].pk.size()) + " got=" +
                      std::to_string(u.slots[i].pk.size()) + ")");
        if (u.slots[i].sk != t.slots[i].sk)
            ok = fail("slot[" + std::to_string(i) + "] sk mismatch (size orig=" +
                      std::to_string(t.slots[i].sk.size()) + " got=" +
                      std::to_string(u.slots[i].sk.size()) + ")");
    }

    // Print size comparison
    off_t yaml_sz = file_size(path);
    std::cout << "YAML file size : " << yaml_sz << " bytes\n";
    std::cout << "Msgpack size   : " << packed.size() << " bytes";
    if (yaml_sz > 0)
        std::cout << " (" << (100 * (long long)packed.size() / yaml_sz) << "% of YAML)";
    std::cout << "\n";
    std::cout << "Tray: " << t.alias << " / " << t.type_str
              << " / " << t.slots.size() << " slots\n";

    if (ok) {
        std::cout << "PASS\n";
        return 0;
    }
    return 1;
}
