#pragma once
#include "tray.hpp"
#include <vector>
#include <cstdint>
#include <string>

namespace tray_mp {
    std::vector<uint8_t> pack(const Tray& tray);
    Tray                 unpack(const std::vector<uint8_t>& data);
    void                 pack_to_file(const Tray& tray, const std::string& path);
    Tray                 unpack_from_file(const std::string& path);
}
