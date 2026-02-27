#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cmath>
#include <unordered_map>
#include <stdexcept>
#include <iomanip>
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static const int    PBKDF2_ITERATIONS = 600000;
static const size_t PBKDF2_SALT_LEN   = 16;
static const size_t PBKDF2_KEY_LEN    = 32;

// Prompt for a password with no echo (termios).
inline std::string read_hidden(const std::string& prompt) {
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

// Returns true if password passes minimum entropy check (>= 80 bits Shannon).
// Prints an error to stderr and returns false if it fails.
inline bool validate_password(const std::string& pw) {
    if (pw.length() < 20) {
        std::cerr << "Error: password must be at least 20 characters (got "
                  << pw.length() << ")\n";
        return false;
    }

    std::unordered_map<char, int> freq;
    for (char ch : pw) freq[ch]++;

    double entropy = 0.0;
    double len = static_cast<double>(pw.length());
    for (auto const& [ch, count] : freq) {
        double p = count / len;
        entropy -= p * std::log2(p);
    }
    double total_entropy = entropy * len;

    if (total_entropy < 80.0) {
        std::cerr << std::fixed << std::setprecision(2);
        std::cerr << "Error: password entropy too low ("
                  << total_entropy << " bits; minimum 80 bits required)\n";
        return false;
    }
    return true;
}

// PBKDF2-HMAC-SHA256: password x salt(16 B) -> key(32 B).
// Uses OpenSSL PKCS5_PBKDF2_HMAC. Throws std::runtime_error on failure.
inline std::vector<uint8_t> pbkdf2_derive(const std::string& password,
                                           const uint8_t* salt) {
    std::vector<uint8_t> key(PBKDF2_KEY_LEN);
    int rc = PKCS5_PBKDF2_HMAC(
        password.data(), static_cast<int>(password.size()),
        salt, static_cast<int>(PBKDF2_SALT_LEN),
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        static_cast<int>(PBKDF2_KEY_LEN), key.data()
    );
    if (rc != 1)
        throw std::runtime_error("PBKDF2 derivation failed");
    return key;
}
