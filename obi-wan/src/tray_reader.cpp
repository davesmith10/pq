#include "tray_reader.hpp"
#include "base64.hpp"
#include "tray_pack.hpp"
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <stdexcept>
#include <string>

// ── YAML parser ───────────────────────────────────────────────────────────────

static std::vector<uint8_t> decode_b64_yaml(const YAML::Node& node) {
    std::string raw = node.as<std::string>();
    // Strip embedded newlines (literal block scalars have them)
    std::string clean;
    clean.reserve(raw.size());
    for (char c : raw) {
        if (c != '\n' && c != '\r' && c != ' ')
            clean += c;
    }
    return base64_decode(clean);
}

static Tray load_tray_yaml(const std::string& path) {
    YAML::Node doc = YAML::LoadFile(path);

    Tray tray;
    tray.version = doc["version"].as<int>(1);
    tray.alias   = doc["alias"].as<std::string>();
    tray.type_str = doc["type"].as<std::string>();
    tray.id      = doc["id"].as<std::string>();
    tray.created = doc["created"].as<std::string>("");
    tray.expires = doc["expires"].as<std::string>("");

    if (tray.type_str == "level2")     tray.tray_type = TrayType::Level2;
    else if (tray.type_str == "level2nist") tray.tray_type = TrayType::Level2NIST;
    else if (tray.type_str == "level3nist") tray.tray_type = TrayType::Level3NIST;
    else if (tray.type_str == "level5nist") tray.tray_type = TrayType::Level5NIST;
    else tray.tray_type = TrayType::Level2; // fallback

    YAML::Node tray_seq = doc["tray"];
    if (!tray_seq || !tray_seq.IsSequence())
        throw std::runtime_error("YAML tray: missing 'tray' sequence");

    for (const auto& slot_node : tray_seq) {
        Slot s;
        s.alg_name = slot_node["alg"].as<std::string>();
        s.pk = decode_b64_yaml(slot_node["pk"]);
        if (slot_node["sk"])
            s.sk = decode_b64_yaml(slot_node["sk"]);
        tray.slots.push_back(std::move(s));
    }

    return tray;
}

// ── Entry point ───────────────────────────────────────────────────────────────

Tray load_tray(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot open tray file: " + path);

    int first = f.get();
    if (first == EOF)
        throw std::runtime_error("Tray file is empty: " + path);

    if (first == 0x2D) {
        // '-' → YAML
        return load_tray_yaml(path);
    } else {
        // msgpack
        return tray_mp::unpack_from_file(path);
    }
}
