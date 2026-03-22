#pragma once
#include <string>
#include <cstdint>

void cmd_gentok(const std::string& tray_path, const std::string& data_str, int64_t ttl_secs);
void cmd_valtok(const std::string& tray_path, const std::string& token_file);
