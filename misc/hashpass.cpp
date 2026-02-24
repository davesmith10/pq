#include <iostream>
#include <string>
#include <unordered_map>
#include <cmath>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <termios.h>
#include <unistd.h>
#include <openssl/evp.h>

static double shannon_entropy(const std::string& input) {
    if (input.empty()) return 0.0;

    std::unordered_map<char, int> freq;
    for (char ch : input)
        freq[ch]++;

    double entropy = 0.0;
    double len = static_cast<double>(input.length());
    for (auto const& [ch, count] : freq) {
        double p = count / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

static std::string read_hidden(const std::string& prompt) {
    std::cerr << prompt << std::flush;

    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    std::string password;
    std::getline(std::cin, password);

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    std::cerr << "\n";
    return password;
}

static std::vector<uint8_t> sha256(const std::string& input) {
    std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int digest_len = 0;
    EVP_Digest(
        input.data(), input.size(),
        digest.data(), &digest_len,
        EVP_sha256(), nullptr
    );
    digest.resize(digest_len);
    return digest;
}

static std::string base64_encode(const std::vector<uint8_t>& data) {
    // EVP_EncodeBlock output: ceil(n/3)*4 bytes + null terminator
    std::vector<unsigned char> out((data.size() + 2) / 3 * 4 + 1);
    int len = EVP_EncodeBlock(out.data(), data.data(), static_cast<int>(data.size()));
    return std::string(reinterpret_cast<char*>(out.data()), static_cast<size_t>(len));
}

int main() {
    std::string password = read_hidden("Enter password: ");

    if (password.length() < 20) {
        std::cerr << "Error: password must be at least 20 characters (got "
                  << password.length() << ")\n";
        return 1;
    }

    double total_entropy = shannon_entropy(password) * static_cast<double>(password.length());
    if (total_entropy < 80.0) {
        std::cerr << std::fixed << std::setprecision(2);
        std::cerr << "Error: password entropy too low ("
                  << total_entropy << " bits; minimum 80 bits required)\n";
        return 1;
    }

    std::vector<uint8_t> hash = sha256(password);
    std::cout << base64_encode(hash) << "\n";
    return 0;
}
