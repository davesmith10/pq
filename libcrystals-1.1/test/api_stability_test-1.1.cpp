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


// Add more tests below





