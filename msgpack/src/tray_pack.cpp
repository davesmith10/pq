#include "tray_pack.hpp"
#include <msgpack.hpp>
#include <fstream>
#include <stdexcept>
#include <string>

namespace tray_mp {

// ── helpers ───────────────────────────────────────────────────────────────────

static TrayType type_str_to_enum(const std::string& s) {
    if (s == "level2")     return TrayType::Level2;
    if (s == "level2nist") return TrayType::Level2NIST;
    if (s == "level3nist") return TrayType::Level3NIST;
    if (s == "level5nist") return TrayType::Level5NIST;
    throw std::runtime_error("Unknown tray type string: " + s);
}

static std::string require_str(const msgpack::object& obj, const char* ctx) {
    if (obj.type != msgpack::type::STR)
        throw std::runtime_error(std::string(ctx) + ": expected string");
    return {obj.via.str.ptr, obj.via.str.size};
}

static std::vector<uint8_t> require_bin(const msgpack::object& obj, const char* ctx) {
    if (obj.type != msgpack::type::BIN)
        throw std::runtime_error(std::string(ctx) + ": expected binary");
    return {reinterpret_cast<const uint8_t*>(obj.via.bin.ptr),
            reinterpret_cast<const uint8_t*>(obj.via.bin.ptr) + obj.via.bin.size};
}

// ── pack ──────────────────────────────────────────────────────────────────────

std::vector<uint8_t> pack(const Tray& tray) {
    msgpack::sbuffer buf;
    msgpack::packer<msgpack::sbuffer> pk(buf);

    pk.pack_map(7);

    // "v" → version
    pk.pack(std::string("v"));
    pk.pack_uint32(static_cast<uint32_t>(tray.version));

    // "a" → alias
    pk.pack(std::string("a"));
    pk.pack(tray.alias);

    // "t" → type_str
    pk.pack(std::string("t"));
    pk.pack(tray.type_str);

    // "id" → UUID
    pk.pack(std::string("id"));
    pk.pack(tray.id);

    // "cr" → created
    pk.pack(std::string("cr"));
    pk.pack(tray.created);

    // "ex" → expires
    pk.pack(std::string("ex"));
    pk.pack(tray.expires);

    // "sl" → slots array
    pk.pack(std::string("sl"));
    pk.pack_array(static_cast<uint32_t>(tray.slots.size()));
    for (const auto& slot : tray.slots) {
        bool has_sk = !slot.sk.empty();
        pk.pack_map(has_sk ? 3 : 2);

        pk.pack(std::string("alg"));
        pk.pack(slot.alg_name);

        pk.pack(std::string("pk"));
        pk.pack_bin(static_cast<uint32_t>(slot.pk.size()));
        pk.pack_bin_body(reinterpret_cast<const char*>(slot.pk.data()), slot.pk.size());

        if (has_sk) {
            pk.pack(std::string("sk"));
            pk.pack_bin(static_cast<uint32_t>(slot.sk.size()));
            pk.pack_bin_body(reinterpret_cast<const char*>(slot.sk.data()), slot.sk.size());
        }
    }

    return {reinterpret_cast<const uint8_t*>(buf.data()),
            reinterpret_cast<const uint8_t*>(buf.data()) + buf.size()};
}

// ── unpack ────────────────────────────────────────────────────────────────────

Tray unpack(const std::vector<uint8_t>& data) {
    msgpack::object_handle oh = msgpack::unpack(
        reinterpret_cast<const char*>(data.data()), data.size());
    const msgpack::object& obj = oh.get();

    if (obj.type != msgpack::type::MAP)
        throw std::runtime_error("unpack: top-level object must be a map");

    Tray tray;
    bool got_v = false, got_a = false, got_t = false, got_id = false,
         got_cr = false, got_ex = false, got_sl = false;

    const auto& map = obj.via.map;
    for (uint32_t i = 0; i < map.size; ++i) {
        const auto& kv = map.ptr[i];
        std::string key = require_str(kv.key, "map key");
        const msgpack::object& val = kv.val;

        if (key == "v") {
            if (val.type != msgpack::type::POSITIVE_INTEGER)
                throw std::runtime_error("unpack: 'v' must be unsigned int");
            tray.version = static_cast<int>(val.via.u64);
            got_v = true;
        } else if (key == "a") {
            tray.alias = require_str(val, "'a'");
            got_a = true;
        } else if (key == "t") {
            tray.type_str = require_str(val, "'t'");
            tray.tray_type = type_str_to_enum(tray.type_str);
            got_t = true;
        } else if (key == "id") {
            tray.id = require_str(val, "'id'");
            got_id = true;
        } else if (key == "cr") {
            tray.created = require_str(val, "'cr'");
            got_cr = true;
        } else if (key == "ex") {
            tray.expires = require_str(val, "'ex'");
            got_ex = true;
        } else if (key == "sl") {
            if (val.type != msgpack::type::ARRAY)
                throw std::runtime_error("unpack: 'sl' must be an array");
            const auto& arr = val.via.array;
            for (uint32_t j = 0; j < arr.size; ++j) {
                const msgpack::object& slot_obj = arr.ptr[j];
                if (slot_obj.type != msgpack::type::MAP)
                    throw std::runtime_error("unpack: slot must be a map");
                Slot slot;
                const auto& smap = slot_obj.via.map;
                for (uint32_t k = 0; k < smap.size; ++k) {
                    const auto& skv = smap.ptr[k];
                    std::string skey = require_str(skv.key, "slot key");
                    if (skey == "alg") {
                        slot.alg_name = require_str(skv.val, "slot 'alg'");
                    } else if (skey == "pk") {
                        slot.pk = require_bin(skv.val, "slot 'pk'");
                    } else if (skey == "sk") {
                        slot.sk = require_bin(skv.val, "slot 'sk'");
                    }
                }
                if (slot.alg_name.empty() || slot.pk.empty())
                    throw std::runtime_error("unpack: slot missing 'alg' or 'pk'");
                tray.slots.push_back(std::move(slot));
            }
            got_sl = true;
        }
    }

    if (!got_v || !got_a || !got_t || !got_id || !got_cr || !got_ex || !got_sl)
        throw std::runtime_error("unpack: missing required fields in msgpack tray");

    return tray;
}

// ── file I/O ──────────────────────────────────────────────────────────────────

void pack_to_file(const Tray& tray, const std::string& path) {
    auto bytes = pack(tray);
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("pack_to_file: cannot open " + path);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    if (!f) throw std::runtime_error("pack_to_file: write error");
}

Tray unpack_from_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("unpack_from_file: cannot open " + path);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    if (!f && !f.eof())
        throw std::runtime_error("unpack_from_file: read error");
    return unpack(bytes);
}

} // namespace tray_mp
