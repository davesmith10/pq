#include <iostream>
#include <string>
#include <unordered_map>
#include <cmath>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <sstream>
#include <termios.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static const int    PBKDF2_ITERATIONS = 600000;
static const size_t PBKDF2_SALT_LEN   = 16;
static const size_t PBKDF2_KEY_LEN    = 32;

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

static std::string hex_encode(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : data)
        oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
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

    // Generate random salt
    std::vector<uint8_t> salt(PBKDF2_SALT_LEN);
    if (RAND_bytes(salt.data(), static_cast<int>(PBKDF2_SALT_LEN)) != 1) {
        std::cerr << "Error: RAND_bytes failed\n";
        return 1;
    }

    // Derive key via PBKDF2-HMAC-SHA256
    std::vector<uint8_t> key(PBKDF2_KEY_LEN);
    int rc = PKCS5_PBKDF2_HMAC(
        password.data(), static_cast<int>(password.size()),
        salt.data(), static_cast<int>(PBKDF2_SALT_LEN),
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        static_cast<int>(PBKDF2_KEY_LEN), key.data()
    );
    if (rc != 1) {
        std::cerr << "Error: PBKDF2 derivation failed\n";
        return 1;
    }

    std::cout << "salt: " << hex_encode(salt) << "\n";
    std::cout << "key:  " << base64_encode(key) << "\n";
    return 0;
}
