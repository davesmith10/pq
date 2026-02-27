#pragma once
#include "tray.hpp"
#include <string>

// Load a Tray from a file path.
// Auto-detects format: if first byte is '-' (0x2D) → YAML, else → msgpack.
// Throws std::runtime_error on failure.
Tray load_tray(const std::string& path);
