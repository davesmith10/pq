#include "pem_io.hpp"
#include "base64.hpp"
#include <fstream>
#include <sstream>
#include <stdexcept>

static const int kLineWidth = 64;

void write_pem(std::ostream& out,
               const std::string& type_header,
               const std::vector<uint8_t>& data)
{
    out << "-----BEGIN " << type_header << "-----\n";

    std::string encoded = base64_encode(data.data(), data.size());
    for (size_t i = 0; i < encoded.size(); i += kLineWidth) {
        out << encoded.substr(i, kLineWidth) << '\n';
    }

    out << "-----END " << type_header << "-----\n";

    if (!out)
        throw std::runtime_error("Write error on PEM output");
}

void write_pem(const std::string& path,
               const std::string& type_header,
               const std::vector<uint8_t>& data)
{
    std::ofstream f(path);
    if (!f)
        throw std::runtime_error("Cannot open file for writing: " + path);

    write_pem(f, type_header, data);

    if (!f)
        throw std::runtime_error("Write error on file: " + path);
}

std::vector<uint8_t> read_pem(const std::string& path,
                               const std::string& expected_type)
{
    std::ifstream f(path);
    if (!f)
        throw std::runtime_error("Cannot open file for reading: " + path);

    std::string begin_marker = "-----BEGIN " + expected_type + "-----";
    std::string end_marker   = "-----END "   + expected_type + "-----";

    std::string line;
    bool found_begin = false;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line == begin_marker) { found_begin = true; break; }
    }
    if (!found_begin)
        throw std::runtime_error("Missing or wrong PEM header in: " + path +
                                 "\n  Expected: " + begin_marker);

    std::string body;
    bool found_end = false;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line == end_marker) { found_end = true; break; }
        body += line;
    }
    if (!found_end)
        throw std::runtime_error("Missing PEM footer in: " + path +
                                 "\n  Expected: " + end_marker);

    return base64_decode(body);
}
