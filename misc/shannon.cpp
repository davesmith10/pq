
#include <iostream>
#include <string>
#include <unordered_map>
#include <cmath>
#include <vector>
#include <iomanip>

double calculateShannonEntropy(const std::string& input) {
    if (input.empty()) return 0.0;

    // 1. Calculate frequency of each character
    std::unordered_map<char, int> freqMap;
    for (char ch : input) {
        freqMap[ch]++;
    }

    double entropy = 0.0;
    double len = static_cast<double>(input.length());

    // 2. Apply Shannon Entropy Formula: H = -sum(pi * log2(pi))
    for (auto const& [ch, count] : freqMap) {
        double p_i = count / len; // Probability of character
        entropy -= p_i * std::log2(p_i);
    }

    return entropy;
}

int main() {
    std::string password;
    std::cout << "Enter password: ";
    std::getline(std::cin, password);

    double entropy = calculateShannonEntropy(password);

    std::cout << "Entropy: " << std::fixed << std::setprecision(4)
              << entropy << " bits" << std::endl;

    return 0;
}


