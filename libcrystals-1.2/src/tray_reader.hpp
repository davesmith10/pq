#pragma once
#include "tray.hpp"
#include <string>

// Load a Tray from a YAML file path.
// Throws std::runtime_error on failure.
Tray load_tray(const std::string& path);
