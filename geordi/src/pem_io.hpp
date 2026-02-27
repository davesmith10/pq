#pragma once
#include <string>
#include <vector>
#include <ostream>
#include <cstdint>

// Write PEM-like armor to a stream.
// type_header: e.g. "DILITHIUM3 PUBLIC KEY"
void write_pem(std::ostream& out,
               const std::string& type_header,
               const std::vector<uint8_t>& data);

// Write PEM-like armor to a file.
void write_pem(const std::string& path,
               const std::string& type_header,
               const std::vector<uint8_t>& data);

// Read and decode a PEM-like armored file.
// expected_type: e.g. "DILITHIUM3 PUBLIC KEY" — validated against the BEGIN line.
std::vector<uint8_t> read_pem(const std::string& path,
                               const std::string& expected_type);
