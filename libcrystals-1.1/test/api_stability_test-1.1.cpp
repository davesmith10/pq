// api_stability_test.cpp — compile-time enforcement of the v1.0 public API.
//
// IMPORTANT: This file MUST compile cleanly.
// DO NOT modify it when adding features — only ADD to it.
// A compile failure here means a breaking API change was introduced.
//
// Only includes crystals/crystals.hpp — no internal headers.

#include "crystals/crystals.hpp"
#include <type_traits>

// ── TrayType enum values added in API 1.1 ────────────────────────────────
static_assert(std::is_same_v<decltype(TrayType::McEliece_Level1), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::McEliece_Level2), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::McEliece_Level3), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::McEliece_Level4), TrayType>);
static_assert(std::is_same_v<decltype(TrayType::McEliece_Level5), TrayType>);


// ── mcs::McElieceKeys struct ──────────────────────────────────────────────
static_assert(std::is_same_v<decltype(mcs::McElieceKeys::pk), std::vector<uint8_t>>);
static_assert(std::is_same_v<decltype(mcs::McElieceKeys::sk), std::vector<uint8_t>>);

// ── mcs::SlhDsaKeys struct ───────────────────────────────────────────────
static_assert(std::is_same_v<decltype(mcs::SlhDsaKeys::pk), std::vector<uint8_t>>);
static_assert(std::is_same_v<decltype(mcs::SlhDsaKeys::sk), std::vector<uint8_t>>);

// ── mcs keygen function signatures ───────────────────────────────────────
static_assert(std::is_same_v<
    decltype(&mcs::keygen_mceliece),
    mcs::McElieceKeys (*)(const std::string&)>);

static_assert(std::is_same_v<
    decltype(&mcs::keygen_slhdsa),
    mcs::SlhDsaKeys (*)(const std::string&)>);

int main() { return 0; }

