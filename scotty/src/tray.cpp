#include "tray.hpp"
#include "ec_ops.hpp"
#include "kyber_ops.hpp"
#include "dilithium_ops.hpp"
#include <fstream>
#include <ctime>
#include <stdexcept>
#include <string>

// ── UUID ──────────────────────────────────────────────────────────────────────

static std::string read_uuid() {
    std::ifstream f("/proc/sys/kernel/random/uuid");
    if (!f)
        throw std::runtime_error("Cannot read UUID from /proc/sys/kernel/random/uuid");
    std::string uuid;
    std::getline(f, uuid);
    return uuid;
}

// ── Timestamps ────────────────────────────────────────────────────────────────

static std::string iso8601_now() {
    std::time_t t = std::time(nullptr);
    struct tm* gmt = std::gmtime(&t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmt);
    return std::string(buf);
}

// Add `years` to an ISO 8601 UTC timestamp string (just increments the year).
static std::string add_years(const std::string& ts, int years) {
    // ts format: "YYYY-MM-DDTHH:MM:SSZ"
    int year = std::stoi(ts.substr(0, 4)) + years;
    return std::to_string(year) + ts.substr(4);
}

// ── Slot factories ────────────────────────────────────────────────────────────

static Slot make_ec_slot(const std::string& name, ec::Algorithm alg) {
    Slot s;
    s.alg_name = name;
    auto kp = ec::keygen(alg);
    s.pk = std::move(kp.pk);
    s.sk = std::move(kp.sk);
    return s;
}

static Slot make_kyber_slot(const std::string& name, int level) {
    Slot s;
    s.alg_name = name;
    kyber::keygen(level, s.pk, s.sk);
    return s;
}

static Slot make_dilithium_slot(const std::string& name, int mode) {
    Slot s;
    s.alg_name = name;
    dilithium::keygen(mode, s.pk, s.sk);
    return s;
}

// ── make_tray ─────────────────────────────────────────────────────────────────

Tray make_tray(TrayType t, const std::string& alias,
               bool classic_only, bool pq_only)
{
    Tray tray;
    tray.version   = 1;
    tray.alias     = alias;
    tray.tray_type = t;
    tray.id        = read_uuid();
    tray.created   = iso8601_now();
    tray.expires   = add_years(tray.created, 2);

    // Slot ordering: KEM-classical, KEM-PQ, Sig-classical, Sig-PQ
    switch (t) {
        case TrayType::Level2:
            tray.type_str = "level2";
            if (!pq_only)      tray.slots.push_back(make_ec_slot("X25519",      ec::Algorithm::X25519));
            if (!classic_only) tray.slots.push_back(make_kyber_slot("Kyber512", 512));
            if (!pq_only)      tray.slots.push_back(make_ec_slot("Ed25519",     ec::Algorithm::Ed25519));
            if (!classic_only) tray.slots.push_back(make_dilithium_slot("Dilithium2", 2));
            break;

        case TrayType::Level2NIST:
            tray.type_str = "level2nist";
            if (!pq_only)      tray.slots.push_back(make_ec_slot("P-256",          ec::Algorithm::P256));
            if (!classic_only) tray.slots.push_back(make_kyber_slot("Kyber512",     512));
            if (!pq_only)      tray.slots.push_back(make_ec_slot("ECDSA P-256",    ec::Algorithm::P256));
            if (!classic_only) tray.slots.push_back(make_dilithium_slot("Dilithium2", 2));
            break;

        case TrayType::Level3NIST:
            tray.type_str = "level3nist";
            if (!pq_only)      tray.slots.push_back(make_ec_slot("P-384",          ec::Algorithm::P384));
            if (!classic_only) tray.slots.push_back(make_kyber_slot("Kyber768",     768));
            if (!pq_only)      tray.slots.push_back(make_ec_slot("ECDSA P-384",    ec::Algorithm::P384));
            if (!classic_only) tray.slots.push_back(make_dilithium_slot("Dilithium3", 3));
            break;

        case TrayType::Level5NIST:
            tray.type_str = "level5nist";
            if (!pq_only)      tray.slots.push_back(make_ec_slot("P-521",          ec::Algorithm::P521));
            if (!classic_only) tray.slots.push_back(make_kyber_slot("Kyber1024",   1024));
            if (!pq_only)      tray.slots.push_back(make_ec_slot("ECDSA P-521",    ec::Algorithm::P521));
            if (!classic_only) tray.slots.push_back(make_dilithium_slot("Dilithium5", 5));
            break;
    }

    return tray;
}
