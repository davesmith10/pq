#include <crystals/crystals.hpp>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

// ── Test helpers ──────────────────────────────────────────────────────────────

static int g_pass = 0, g_fail = 0;

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr); \
            ++g_fail; \
        } else { \
            ++g_pass; \
        } \
    } while(0)

#define CHECK_THROWS(expr) \
    do { \
        bool caught = false; \
        try { (void)(expr); } catch (...) { caught = true; } \
        if (!caught) { \
            std::fprintf(stderr, "FAIL [%s:%d]: expected exception: %s\n", __FILE__, __LINE__, #expr); \
            ++g_fail; \
        } else { \
            ++g_pass; \
        } \
    } while(0)

static bool uuid_is_v8(const std::string& id) {
    // Format: xxxxxxxx-xxxx-8xxx-xxxx-xxxxxxxxxxxx (position 14 must be '8')
    return id.size() == 36 && id[14] == '8' && id[8] == '-' && id[13] == '-';
}

static std::string tmp_path(const char* name) {
    return std::string("/tmp/crystals_test_") + name;
}

// ── Section 1: Keygen ─────────────────────────────────────────────────────────

static void test_keygen() {
    std::printf("=== Section 1: Keygen ===\n");

    struct Case { TrayType t; const char* name; size_t slots; };
    Case cases[] = {
        { TrayType::Level0,       "level0",       2 },
        { TrayType::Level1,       "level1",       2 },
        { TrayType::Level2_25519, "level2-25519", 4 },
        { TrayType::Level2,       "level2",       4 },
        { TrayType::Level3,       "level3",       4 },
        { TrayType::Level5,       "level5",       4 },
    };

    for (auto& c : cases) {
        Tray tray = make_tray(c.t, "alice");
        CHECK(tray.slots.size() == c.slots);
        CHECK(!tray.id.empty());
        CHECK(uuid_is_v8(tray.id));
        CHECK(tray.alias == "alice");
        CHECK(tray.profile_group == "crystals");

        for (const auto& slot : tray.slots) {
            CHECK(!slot.pk.empty());
            CHECK(!slot.sk.empty());
        }

        // make_public_tray: same UUID, sk cleared
        Tray pub = make_public_tray(tray);
        CHECK(pub.id == tray.id);
        CHECK(pub.alias == "alice.pub");
        for (const auto& slot : pub.slots)
            CHECK(slot.sk.empty());

        std::printf("  %s: OK\n", c.name);
    }
}

// ── Section 2: YAML round-trip ────────────────────────────────────────────────

static void test_yaml_roundtrip() {
    std::printf("=== Section 2: YAML round-trip ===\n");

    Tray orig = make_tray(TrayType::Level2_25519, "bob");
    std::string yaml = emit_tray_yaml(orig);
    CHECK(!yaml.empty());

    // Write to temp file, then load_tray
    std::string path = tmp_path("yaml.tray");
    {
        std::ofstream f(path);
        f << yaml;
    }

    Tray loaded = load_tray(path);
    CHECK(loaded.id == orig.id);
    CHECK(loaded.alias == orig.alias);
    CHECK(loaded.slots.size() == orig.slots.size());
    for (size_t i = 0; i < orig.slots.size(); ++i) {
        CHECK(loaded.slots[i].alg_name == orig.slots[i].alg_name);
        CHECK(loaded.slots[i].pk == orig.slots[i].pk);
        CHECK(loaded.slots[i].sk == orig.slots[i].sk);
    }
    std::printf("  level2-25519 YAML round-trip: OK\n");
}

// ── Section 3: Msgpack round-trip ─────────────────────────────────────────────

static void test_msgpack_roundtrip() {
    std::printf("=== Section 3: Msgpack round-trip ===\n");

    Tray orig = make_tray(TrayType::Level3, "carol");

    // In-memory pack/unpack
    auto packed = tray_mp::pack(orig);
    CHECK(!packed.empty());
    CHECK(packed[0] != '-');  // not YAML

    Tray rt = tray_mp::unpack(packed);
    CHECK(rt.id == orig.id);
    CHECK(rt.alias == orig.alias);
    CHECK(rt.slots.size() == orig.slots.size());

    // File pack/unpack
    std::string path = tmp_path("msgpack.tray");
    tray_mp::pack_to_file(orig, path);
    Tray rt2 = tray_mp::unpack_from_file(path);
    CHECK(rt2.id == orig.id);

    // load_tray auto-detect
    Tray rt3 = load_tray(path);
    CHECK(rt3.id == orig.id);
    CHECK(rt3.slots.size() == orig.slots.size());
    for (size_t i = 0; i < orig.slots.size(); ++i) {
        CHECK(rt3.slots[i].pk == orig.slots[i].pk);
        CHECK(rt3.slots[i].sk == orig.slots[i].sk);
    }

    std::printf("  level3 msgpack round-trip: OK\n");
}

// ── Section 4: UUID verification ──────────────────────────────────────────────

static void test_uuid_verification() {
    std::printf("=== Section 4: UUID verification ===\n");

    Tray orig = make_tray(TrayType::Level2_25519, "dave");
    auto packed = tray_mp::pack(orig);

    // Tamper: flip one pk byte
    // Find the pk of first slot in the msgpack data and flip a byte
    // Simpler: write to file, flip a byte, try to load_tray
    std::string path = tmp_path("tampered.tray");
    tray_mp::pack_to_file(orig, path);

    // Tamper: flip a byte near the middle of the file
    {
        std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
        f.seekg(0, std::ios::end);
        size_t sz = f.tellg();
        f.seekp(sz / 2);
        char c; f.get(c); f.seekp(sz / 2); f.put(c ^ 0xFF);
    }

    // load_tray should either throw UUID mismatch or msgpack parse error
    bool threw = false;
    try {
        load_tray(path);
    } catch (const std::runtime_error&) {
        threw = true;
    } catch (...) {
        threw = true;
    }
    CHECK(threw);
    std::printf("  tampered msgpack rejected: OK\n");
}

// ── Section 5: Kyber KEM ──────────────────────────────────────────────────────

static void test_kyber_kem() {
    std::printf("=== Section 5: Kyber KEM ===\n");

    for (int level : {512, 768, 1024}) {
        std::vector<uint8_t> pk, sk;
        kyber::keygen(level, pk, sk);

        auto sz = kyber_kem_sizes(level);
        CHECK(pk.size() == sz.pk_bytes);
        CHECK(sk.size() == sz.sk_bytes);

        std::vector<uint8_t> ct, ss_enc, ss_dec;
        kyber_kem::encaps(level, pk, ct, ss_enc);
        CHECK(ct.size() == sz.ct_bytes);
        CHECK(ss_enc.size() == sz.ss_bytes);

        kyber_kem::decaps(level, sk, ct, ss_dec);
        CHECK(ss_enc == ss_dec);

        std::printf("  Kyber%d KEM: OK\n", level);
    }
}

// ── Section 6: EC KEM ─────────────────────────────────────────────────────────

static void test_ec_kem() {
    std::printf("=== Section 6: EC KEM ===\n");

    struct Case { const char* alg; ec::Algorithm alg_enum; };
    Case cases[] = {
        { "X25519", ec::Algorithm::X25519 },
        { "P-256",  ec::Algorithm::P256   },
        { "P-384",  ec::Algorithm::P384   },
        { "P-521",  ec::Algorithm::P521   },
    };

    for (auto& c : cases) {
        auto kp = ec::keygen(c.alg_enum);
        CHECK(!kp.pk.empty());
        CHECK(!kp.sk.empty());

        std::vector<uint8_t> ct, ss_enc, ss_dec;
        ec_kem::encaps(c.alg, kp.pk, ct, ss_enc);
        CHECK(!ct.empty());
        CHECK(!ss_enc.empty());

        ec_kem::decaps(c.alg, kp.sk, ct, ss_dec);
        CHECK(ss_enc == ss_dec);

        std::printf("  %s EC KEM: OK\n", c.alg);
    }
}

// ── Section 7: Dilithium sign/verify ─────────────────────────────────────────

static void test_dilithium_sig() {
    std::printf("=== Section 7: Dilithium sign/verify ===\n");

    std::vector<uint8_t> msg = {0x01, 0x02, 0x03, 0x04, 0x05};

    for (int mode : {2, 3, 5}) {
        std::vector<uint8_t> pk, sk;
        dilithium::keygen(mode, pk, sk);

        auto sz = dilithium_sizes(mode);
        CHECK(pk.size() == sz.pk_bytes);
        CHECK(sk.size() == sz.sk_bytes);

        std::vector<uint8_t> sig;
        dilithium_sig::sign(mode, sk, msg, sig);
        CHECK(!sig.empty());

        bool ok = dilithium_sig::verify(mode, pk, msg, sig);
        CHECK(ok);

        // Tampered message should fail
        std::vector<uint8_t> bad_msg = msg;
        bad_msg[0] ^= 0xFF;
        bool bad_ok = dilithium_sig::verify(mode, pk, bad_msg, sig);
        CHECK(!bad_ok);

        std::printf("  Dilithium%d sign/verify: OK\n", mode);
    }
}

// ── Section 8: EC sign/verify ─────────────────────────────────────────────────

static void test_ec_sig() {
    std::printf("=== Section 8: EC sign/verify ===\n");

    std::vector<uint8_t> msg = {0xDE, 0xAD, 0xBE, 0xEF};

    struct Case { const char* alg; ec::Algorithm alg_enum; size_t expected_sig; };
    Case cases[] = {
        { "Ed25519",    ec::Algorithm::Ed25519, 64  },
        { "ECDSA P-256", ec::Algorithm::P256,   64  },
        { "ECDSA P-384", ec::Algorithm::P384,   96  },
        { "ECDSA P-521", ec::Algorithm::P521,   132 },
    };

    for (auto& c : cases) {
        auto kp = ec::keygen(c.alg_enum);

        std::vector<uint8_t> sig;
        ec_sig::sign(c.alg, kp.sk, msg, sig);
        CHECK(sig.size() == c.expected_sig);

        bool ok = ec_sig::verify(c.alg, kp.pk, msg, sig);
        CHECK(ok);

        // Tampered sig should fail
        std::vector<uint8_t> bad_sig = sig;
        bad_sig[0] ^= 0xFF;
        bool bad_ok = ec_sig::verify(c.alg, kp.pk, msg, bad_sig);
        CHECK(!bad_ok);

        std::printf("  %s sign/verify: OK\n", c.alg);
    }
}

// ── Section 9: OBIWAN armor ───────────────────────────────────────────────────

static void test_obiwan_armor() {
    std::printf("=== Section 9: OBIWAN armor ===\n");

    WireHeader hdr;
    hdr.kdf    = KDFAlg::SHAKE256;
    hdr.cipher = CipherAlg::AES256GCM;
    hdr.ct_classical = {0x01, 0x02, 0x03, 0x04};
    hdr.ct_pq        = {0xAA, 0xBB, 0xCC};

    std::vector<uint8_t> payload = {0x11, 0x22, 0x33, 0x44, 0x55};

    std::string armored = armor_pack(hdr, payload);
    CHECK(armored.find("-----BEGIN OBIWAN ENCRYPTED FILE-----") != std::string::npos);
    CHECK(armored.find("-----END OBIWAN ENCRYPTED FILE-----") != std::string::npos);

    std::vector<uint8_t> payload_out;
    WireHeader hdr2 = armor_unpack(armored, payload_out);
    CHECK((uint8_t)hdr2.kdf    == (uint8_t)hdr.kdf);
    CHECK((uint8_t)hdr2.cipher == (uint8_t)hdr.cipher);
    CHECK(hdr2.ct_classical == hdr.ct_classical);
    CHECK(hdr2.ct_pq == hdr.ct_pq);
    CHECK(payload_out == payload);

    std::printf("  armor_pack/unpack round-trip: OK\n");
}

// ── Section 10: AES-256-GCM + ChaCha20 ────────────────────────────────────────

static void test_symmetric() {
    std::printf("=== Section 10: AES-256-GCM + ChaCha20 ===\n");

    uint8_t key[32];
    std::memset(key, 0x42, 32);

    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"

    // AES-256-GCM no AAD
    {
        auto blob = aes256gcm_encrypt(key, plaintext);
        CHECK(blob.size() >= 12 + 16 + plaintext.size());
        auto pt = aes256gcm_decrypt(key, blob);
        CHECK(pt == plaintext);

        // Tampered blob should throw
        auto bad = blob;
        bad[bad.size() / 2] ^= 0xFF;
        CHECK_THROWS(aes256gcm_decrypt(key, bad));
        std::printf("  AES-256-GCM: OK\n");
    }

    // AES-256-GCM with AAD
    {
        std::vector<uint8_t> aad = {0x01, 0x02};
        auto blob = aes256gcm_encrypt_aad(key, plaintext, aad.data(), aad.size());
        auto pt = aes256gcm_decrypt_aad(key, blob, aad.data(), aad.size());
        CHECK(pt == plaintext);

        // Wrong AAD should throw
        std::vector<uint8_t> bad_aad = {0xFF, 0xFF};
        CHECK_THROWS(aes256gcm_decrypt_aad(key, blob, bad_aad.data(), bad_aad.size()));
        std::printf("  AES-256-GCM with AAD: OK\n");
    }

    // ChaCha20-Poly1305
    {
        auto blob = chacha20poly1305_encrypt(key, plaintext);
        CHECK(blob.size() >= 12 + 16 + plaintext.size());
        auto pt = chacha20poly1305_decrypt(key, blob);
        CHECK(pt == plaintext);

        auto bad = blob;
        bad[bad.size() / 2] ^= 0xFF;
        CHECK_THROWS(chacha20poly1305_decrypt(key, bad));
        std::printf("  ChaCha20-Poly1305: OK\n");
    }
}

// ── Section 11: pw wire format ────────────────────────────────────────────────

static void test_pw_wire_format() {
    std::printf("=== Section 11: pw wire format ===\n");

    for (int level : {512, 768, 1024}) {
        auto sz = kyber_kem_sizes(level);

        PwBundle b;
        b.level = level;
        std::memset(b.salt, 0xAB, 32);
        b.scrypt_n_log2 = 16;
        b.scrypt_r = 8;
        b.scrypt_p = 1;
        b.pk.assign(sz.pk_bytes, 0x11);
        b.ct.assign(sz.ct_bytes, 0x22);
        b.wrap_nonce_tag_sk_enc.assign(12 + 16 + sz.sk_bytes, 0x33);
        b.data_nonce_tag_ct.assign(12 + 16 + 100, 0x44);

        auto wire = pack_pw_bundle(b);

        // Check AAD prefix
        auto aad = pw_bundle_aad(level);
        CHECK(aad.size() == 7);
        CHECK(aad[0] == 'O' && aad[1] == 'B' && aad[2] == 'W' && aad[3] == 'E');

        // Round-trip
        PwBundle b2 = parse_pw_bundle(wire);
        CHECK(b2.level == b.level);
        CHECK(std::memcmp(b2.salt, b.salt, 32) == 0);
        CHECK(b2.scrypt_n_log2 == b.scrypt_n_log2);
        CHECK(b2.pk == b.pk);
        CHECK(b2.ct == b.ct);
        CHECK(b2.wrap_nonce_tag_sk_enc == b.wrap_nonce_tag_sk_enc);
        CHECK(b2.data_nonce_tag_ct == b.data_nonce_tag_ct);

        // Armor/dearmor
        auto armored = armor_pw(wire);
        CHECK(armored.find("-----BEGIN OBIWAN PW ENCRYPTED FILE-----") != std::string::npos);
        auto wire2 = dearmor_pw(armored);
        CHECK(wire2 == wire);

        std::printf("  pw wire Kyber%d round-trip: OK\n", level);
    }
}

// ── main ──────────────────────────────────────────────────────────────────────

int main() {
    std::printf("crystals library test\n");
    std::printf("=====================\n\n");

    try {
        test_keygen();
        test_yaml_roundtrip();
        test_msgpack_roundtrip();
        test_uuid_verification();
        test_kyber_kem();
        test_ec_kem();
        test_dilithium_sig();
        test_ec_sig();
        test_obiwan_armor();
        test_symmetric();
        test_pw_wire_format();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "UNCAUGHT EXCEPTION: %s\n", e.what());
        return 1;
    }

    std::printf("\n=====================\n");
    std::printf("Results: %d passed, %d failed\n", g_pass, g_fail);

    return (g_fail == 0) ? 0 : 1;
}
