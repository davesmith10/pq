#pragma once
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>

// AES-256-GCM helpers using OpenSSL EVP (no deprecated APIs).
// Key must be exactly 32 bytes (256 bits).
// Nonce is 12 bytes (96-bit, GCM standard).
// Tag  is 16 bytes (128-bit).

static constexpr int AES_GCM_NONCE_LEN = 12;
static constexpr int AES_GCM_TAG_LEN   = 16;

// Encrypt plaintext.
// Returns: nonce(12) || tag(16) || ciphertext(N)
inline std::vector<uint8_t> aes256gcm_encrypt(
    const uint8_t key[32],
    const std::vector<uint8_t>& plaintext)
{
    // Generate random nonce
    uint8_t nonce[AES_GCM_NONCE_LEN];
    if (RAND_bytes(nonce, AES_GCM_NONCE_LEN) != 1)
        throw std::runtime_error("RAND_bytes failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    auto cleanup = [&]{ EVP_CIPHER_CTX_free(ctx); };

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        cleanup(); throw std::runtime_error("EVP_EncryptInit_ex (cipher) failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_LEN, nullptr) != 1) {
        cleanup(); throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        cleanup(); throw std::runtime_error("EVP_EncryptInit_ex (key/iv) failed");
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    int len = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                              plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            cleanup(); throw std::runtime_error("EVP_EncryptUpdate failed");
        }
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len) != 1) {
        cleanup(); throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext.resize(static_cast<size_t>(len + final_len));

    uint8_t tag[AES_GCM_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, tag) != 1) {
        cleanup(); throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
    }
    cleanup();

    // Assemble nonce || tag || ciphertext
    std::vector<uint8_t> out;
    out.reserve(AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN + ciphertext.size());
    out.insert(out.end(), nonce, nonce + AES_GCM_NONCE_LEN);
    out.insert(out.end(), tag,   tag   + AES_GCM_TAG_LEN);
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    return out;
}

// Decrypt.  Input: nonce(12) || tag(16) || ciphertext(N)
// Returns plaintext. Throws on authentication failure.
inline std::vector<uint8_t> aes256gcm_decrypt(
    const uint8_t key[32],
    const std::vector<uint8_t>& nonce_tag_ct)
{
    if (nonce_tag_ct.size() < static_cast<size_t>(AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN))
        throw std::runtime_error("AES-GCM input too short");

    const uint8_t* nonce      = nonce_tag_ct.data();
    const uint8_t* tag        = nonce_tag_ct.data() + AES_GCM_NONCE_LEN;
    const uint8_t* ciphertext = nonce_tag_ct.data() + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN;
    size_t         ct_len     = nonce_tag_ct.size() - AES_GCM_NONCE_LEN - AES_GCM_TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    auto cleanup = [&]{ EVP_CIPHER_CTX_free(ctx); };

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        cleanup(); throw std::runtime_error("EVP_DecryptInit_ex (cipher) failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_LEN, nullptr) != 1) {
        cleanup(); throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        cleanup(); throw std::runtime_error("EVP_DecryptInit_ex (key/iv) failed");
    }

    std::vector<uint8_t> plaintext(ct_len);
    int len = 0;
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                              ciphertext, static_cast<int>(ct_len)) != 1) {
            cleanup(); throw std::runtime_error("EVP_DecryptUpdate failed");
        }
    }

    // Set expected tag before finalising
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN,
                             const_cast<uint8_t*>(tag)) != 1) {
        cleanup(); throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");
    }

    int final_len = 0;
    int rc = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len);
    cleanup();

    if (rc != 1)
        throw std::runtime_error("AES-GCM decryption failed (authentication)");

    plaintext.resize(static_cast<size_t>(len + final_len));
    return plaintext;
}
