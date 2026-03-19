#pragma once
// Umbrella header — includes all crystals library components in dependency order.

// ── Domain model ─────────────────────────────────────────────────────────────
#include <crystals/tray.hpp>

// ── Merged C API declarations ─────────────────────────────────────────────────
#include <crystals/kyber_api.hpp>
#include <crystals/dilithium_api.hpp>

// ── Key generation ────────────────────────────────────────────────────────────
#include <crystals/base64.hpp>
#include <crystals/ec_ops.hpp>
#include <crystals/kyber_ops.hpp>
#include <crystals/dilithium_ops.hpp>

// ── I/O (YAML + msgpack) ──────────────────────────────────────────────────────
#include <crystals/yaml_io.hpp>
#include <crystals/tray_reader.hpp>
#include <crystals/tray_pack.hpp>

// ── KEM (encaps/decaps) ───────────────────────────────────────────────────────
#include <crystals/ec_kem.hpp>
#include <crystals/kyber_kem.hpp>

// ── Signatures ────────────────────────────────────────────────────────────────
#include <crystals/ec_sig.hpp>
#include <crystals/dilithium_sig.hpp>

// ── Symmetric + KDF ───────────────────────────────────────────────────────────
#include <crystals/kdf.hpp>
#include <crystals/symmetric.hpp>

// ── Tray protection ───────────────────────────────────────────────────────────
#include <crystals/secure_tray.hpp>

// ── Wire formats ─────────────────────────────────────────────────────────────
#include <crystals/armor.hpp>
#include <crystals/hyke_format.hpp>
#include <crystals/pw_format.hpp>
#include <crystals/pw_crypt.hpp>
#include <crystals/token_format.hpp>
#include <crystals/token_cmd.hpp>
