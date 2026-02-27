#pragma once
#include "tray.hpp"
#include <string>

// Emit the full tray as YAML to a string.
std::string emit_tray_yaml(const Tray& tray);
