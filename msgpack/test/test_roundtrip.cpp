#include "tray_pack.hpp"
#include <iostream>
#include <cstring>

static bool fail(const char* msg) {
    std::cerr << "FAIL: " << msg << "\n";
    return false;
}

static bool check(bool cond, const char* msg) {
    if (!cond) return fail(msg);
    return true;
}

int main() {
    // Build a mock Tray with known values
    Tray t;
    t.version   = 1;
    t.alias     = "testuser";
    t.type_str  = "level3nist";
    t.tray_type = TrayType::Level3NIST;
    t.id        = "12345678-abcd-4000-8000-deadbeefcafe";
    t.created   = "2026-01-01T00:00:00Z";
    t.expires   = "2028-01-01T00:00:00Z";
    t.is_public = false;

    // Slot 0: X25519 — mock 32-byte pk and sk
    {
        Slot s;
        s.alg_name = "X25519";
        s.pk = std::vector<uint8_t>(32, 0xAA);
        s.sk = std::vector<uint8_t>(32, 0xBB);
        t.slots.push_back(s);
    }
    // Slot 1: Kyber768 — mock pk (1184 B) and sk (2400 B)
    {
        Slot s;
        s.alg_name = "Kyber768";
        s.pk = std::vector<uint8_t>(1184, 0x01);
        s.sk = std::vector<uint8_t>(2400, 0x02);
        t.slots.push_back(s);
    }
    // Slot 2: Ed25519 — mock 32-byte pk, empty sk (public-only slot)
    {
        Slot s;
        s.alg_name = "Ed25519";
        s.pk = std::vector<uint8_t>(32, 0xCC);
        // sk deliberately empty
        t.slots.push_back(s);
    }
    // Slot 3: Dilithium3 — mock pk (1952 B) and sk (4032 B)
    {
        Slot s;
        s.alg_name = "Dilithium3";
        s.pk = std::vector<uint8_t>(1952, 0x03);
        s.sk = std::vector<uint8_t>(4032, 0x04);
        t.slots.push_back(s);
    }

    // Pack
    std::vector<uint8_t> packed = tray_mp::pack(t);
    std::cout << "Packed size: " << packed.size() << " bytes\n";

    // Unpack
    Tray u;
    try {
        u = tray_mp::unpack(packed);
    } catch (const std::exception& e) {
        std::cerr << "FAIL: unpack threw: " << e.what() << "\n";
        return 1;
    }

    bool ok = true;
    ok &= check(u.version   == t.version,   "version mismatch");
    ok &= check(u.alias     == t.alias,     "alias mismatch");
    ok &= check(u.type_str  == t.type_str,  "type_str mismatch");
    ok &= check(u.tray_type == t.tray_type, "tray_type mismatch");
    ok &= check(u.id        == t.id,        "id mismatch");
    ok &= check(u.created   == t.created,   "created mismatch");
    ok &= check(u.expires   == t.expires,   "expires mismatch");
    ok &= check(u.slots.size() == t.slots.size(), "slots.size() mismatch");

    for (size_t i = 0; i < t.slots.size() && i < u.slots.size(); ++i) {
        ok &= check(u.slots[i].alg_name == t.slots[i].alg_name,
                    ("slot alg_name mismatch at index " + std::to_string(i)).c_str());
        ok &= check(u.slots[i].pk == t.slots[i].pk,
                    ("slot pk mismatch at index " + std::to_string(i)).c_str());
        ok &= check(u.slots[i].sk == t.slots[i].sk,
                    ("slot sk mismatch at index " + std::to_string(i)).c_str());
    }

    if (ok) {
        std::cout << "PASS\n";
        return 0;
    }
    return 1;
}
