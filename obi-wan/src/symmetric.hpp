#pragma once
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>

// AES-256-GCM and ChaCha20-Poly1305 AEAD helpers.
// All functions output/expect: nonce(12) || tag(16) || ciphertext(N)

static constexpr int AEAD_NONCE_LEN = 12;
static constexpr int AEAD_TAG_LEN   = 16;

// ── AES-256-GCM ──────────────────────────────────────────────────────────────

inline std::vector<uint8_t> aes256gcm_encrypt(
    const uint8_t key[32],
    const std::vector<uint8_t>& plaintext)
{
    uint8_t nonce[AEAD_NONCE_LEN];
    if (RAND_bytes(nonce, AEAD_NONCE_LEN) != 1)
        throw std::runtime_error("RAND_bytes failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AEAD_NONCE_LEN, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-256-GCM encrypt init failed");
    }

    std::vector<uint8_t> ct(plaintext.size());
    int len = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ct.data(), &len,
                              plaintext.data(), (int)plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM EncryptUpdate failed");
        }
    }
    int flen = 0;
    if (EVP_EncryptFinal_ex(ctx, ct.data() + len, &flen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-256-GCM EncryptFinal failed");
    }
    ct.resize((size_t)(len + flen));

    uint8_t tag[AEAD_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AEAD_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-256-GCM GET_TAG failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> out;
    out.reserve(AEAD_NONCE_LEN + AEAD_TAG_LEN + ct.size());
    out.insert(out.end(), nonce, nonce + AEAD_NONCE_LEN);
    out.insert(out.end(), tag,   tag   + AEAD_TAG_LEN);
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

inline std::vector<uint8_t> aes256gcm_decrypt(
    const uint8_t key[32],
    const std::vector<uint8_t>& nonce_tag_ct)
{
    if (nonce_tag_ct.size() < (size_t)(AEAD_NONCE_LEN + AEAD_TAG_LEN))
        throw std::runtime_error("AES-256-GCM input too short");

    const uint8_t* nonce = nonce_tag_ct.data();
    const uint8_t* tag   = nonce_tag_ct.data() + AEAD_NONCE_LEN;
    const uint8_t* ct    = nonce_tag_ct.data() + AEAD_NONCE_LEN + AEAD_TAG_LEN;
    size_t ct_len        = nonce_tag_ct.size() - AEAD_NONCE_LEN - AEAD_TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AEAD_NONCE_LEN, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-256-GCM decrypt init failed");
    }

    std::vector<uint8_t> pt(ct_len);
    int len = 0;
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, pt.data(), &len, ct, (int)ct_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM DecryptUpdate failed");
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AEAD_TAG_LEN,
                             const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-256-GCM SET_TAG failed");
    }

    int flen = 0;
    int rc = EVP_DecryptFinal_ex(ctx, pt.data() + len, &flen);
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1)
        throw std::runtime_error("AES-256-GCM authentication failed");

    pt.resize((size_t)(len + flen));
    return pt;
}

// ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────────

inline std::vector<uint8_t> chacha20poly1305_encrypt(
    const uint8_t key[32],
    const std::vector<uint8_t>& plaintext)
{
    uint8_t nonce[AEAD_NONCE_LEN];
    if (RAND_bytes(nonce, AEAD_NONCE_LEN) != 1)
        throw std::runtime_error("RAND_bytes failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AEAD_NONCE_LEN, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("ChaCha20-Poly1305 encrypt init failed");
    }

    std::vector<uint8_t> ct(plaintext.size());
    int len = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ct.data(), &len,
                              plaintext.data(), (int)plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("ChaCha20-Poly1305 EncryptUpdate failed");
        }
    }
    int flen = 0;
    if (EVP_EncryptFinal_ex(ctx, ct.data() + len, &flen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("ChaCha20-Poly1305 EncryptFinal failed");
    }
    ct.resize((size_t)(len + flen));

    uint8_t tag[AEAD_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("ChaCha20-Poly1305 GET_TAG failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> out;
    out.reserve(AEAD_NONCE_LEN + AEAD_TAG_LEN + ct.size());
    out.insert(out.end(), nonce, nonce + AEAD_NONCE_LEN);
    out.insert(out.end(), tag,   tag   + AEAD_TAG_LEN);
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

inline std::vector<uint8_t> chacha20poly1305_decrypt(
    const uint8_t key[32],
    const std::vector<uint8_t>& nonce_tag_ct)
{
    if (nonce_tag_ct.size() < (size_t)(AEAD_NONCE_LEN + AEAD_TAG_LEN))
        throw std::runtime_error("ChaCha20-Poly1305 input too short");

    const uint8_t* nonce = nonce_tag_ct.data();
    const uint8_t* tag   = nonce_tag_ct.data() + AEAD_NONCE_LEN;
    const uint8_t* ct    = nonce_tag_ct.data() + AEAD_NONCE_LEN + AEAD_TAG_LEN;
    size_t ct_len        = nonce_tag_ct.size() - AEAD_NONCE_LEN - AEAD_TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AEAD_NONCE_LEN, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("ChaCha20-Poly1305 decrypt init failed");
    }

    std::vector<uint8_t> pt(ct_len);
    int len = 0;
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, pt.data(), &len, ct, (int)ct_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("ChaCha20-Poly1305 DecryptUpdate failed");
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_LEN,
                             const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("ChaCha20-Poly1305 SET_TAG failed");
    }

    int flen = 0;
    int rc = EVP_DecryptFinal_ex(ctx, pt.data() + len, &flen);
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1)
        throw std::runtime_error("ChaCha20-Poly1305 authentication failed");

    pt.resize((size_t)(len + flen));
    return pt;
}
