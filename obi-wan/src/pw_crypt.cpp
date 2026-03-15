#include "pw_crypt.hpp"
#include "pw_format.hpp"
#include "kyber_api.hpp"
#include "symmetric.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <stdexcept>

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/ui.h>

extern "C" {
#include "scrypt-kdf.h"
}

// ── Helpers ──────────────────────────────────────────────────────────────────

static std::vector<uint8_t> read_file_pw(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot open file: " + path);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

static void write_file_pw(const std::string& path, const std::string& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot write file: " + path);
    f.write(data.data(), (std::streamsize)data.size());
}

static void write_file_pw(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot write file: " + path);
    f.write((const char*)data.data(), (std::streamsize)data.size());
}

static std::string read_file_text_pw(const std::string& path) {
    std::ifstream f(path);
    if (!f)
        throw std::runtime_error("Cannot open file: " + path);
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

// Read first line of a file into buf (for --pwfile).
// Returns true on success.
static bool read_pwfile(const std::string& path, char* buf, int buflen) {
    std::ifstream f(path);
    if (!f) {
        std::cerr << "Error: cannot open pwfile: " << path << "\n";
        return false;
    }
    std::string line;
    std::getline(f, line);
    if ((int)line.size() >= buflen) {
        std::cerr << "Error: password in pwfile is too long\n";
        return false;
    }
    std::memcpy(buf, line.data(), line.size());
    buf[line.size()] = '\0';
    return true;
}

// Prompt for password (twice for encryption, once for decryption).
// Returns false on failure.
static bool prompt_password_confirm(char* buf, int buflen) {
    char verify[256] = {};
    if (buflen > (int)sizeof(verify))
        buflen = (int)sizeof(verify);

    if (EVP_read_pw_string(buf, buflen, "Enter password: ", 0) != 0)
        return false;
    if (EVP_read_pw_string(verify, (int)sizeof(verify), "Confirm password: ", 0) != 0) {
        OPENSSL_cleanse(verify, sizeof(verify));
        return false;
    }

    bool match = (std::strcmp(buf, verify) == 0);
    OPENSSL_cleanse(verify, sizeof(verify));
    return match;
}

static bool prompt_password_once(char* buf, int buflen) {
    return EVP_read_pw_string(buf, buflen, "Enter password: ", 0) == 0;
}

// Run scrypt KDF. Throws on error.
static void run_scrypt(const char* passwd, size_t passwd_len,
                       const uint8_t* salt, size_t salt_len,
                       uint8_t n_log2, uint8_t r, uint8_t p,
                       uint8_t* out, size_t out_len)
{
    uint64_t N = (uint64_t)1 << n_log2;
    if (scrypt_kdf((const uint8_t*)passwd, passwd_len,
                   salt, salt_len,
                   N, (uint32_t)r, (uint32_t)p,
                   out, out_len) != 0)
        throw std::runtime_error("scrypt KDF failed");
}

// Kyber keypair dispatch
static void kyber_keypair(int level, std::vector<uint8_t>& pk, std::vector<uint8_t>& sk) {
    auto sz = kyber_kem_sizes(level);
    pk.resize(sz.pk_bytes);
    sk.resize(sz.sk_bytes);
    int rc = 0;
    if      (level == 512)  rc = pqcrystals_kyber512_ref_keypair(pk.data(), sk.data());
    else if (level == 768)  rc = pqcrystals_kyber768_ref_keypair(pk.data(), sk.data());
    else                    rc = pqcrystals_kyber1024_ref_keypair(pk.data(), sk.data());
    if (rc != 0) throw std::runtime_error("Kyber keypair generation failed");
}

// Kyber encaps dispatch → ct, ss
static void kyber_encaps(int level, const std::vector<uint8_t>& pk,
                         std::vector<uint8_t>& ct, std::vector<uint8_t>& ss)
{
    auto sz = kyber_kem_sizes(level);
    ct.resize(sz.ct_bytes);
    ss.resize(sz.ss_bytes);
    int rc = 0;
    if      (level == 512)  rc = pqcrystals_kyber512_ref_enc(ct.data(), ss.data(), pk.data());
    else if (level == 768)  rc = pqcrystals_kyber768_ref_enc(ct.data(), ss.data(), pk.data());
    else                    rc = pqcrystals_kyber1024_ref_enc(ct.data(), ss.data(), pk.data());
    if (rc != 0) throw std::runtime_error("Kyber encaps failed");
}

// Kyber decaps dispatch → ss
static void kyber_decaps(int level, const std::vector<uint8_t>& sk,
                         const std::vector<uint8_t>& ct, std::vector<uint8_t>& ss)
{
    auto sz = kyber_kem_sizes(level);
    ss.resize(sz.ss_bytes);
    int rc = 0;
    if      (level == 512)  rc = pqcrystals_kyber512_ref_dec(ss.data(), ct.data(), sk.data());
    else if (level == 768)  rc = pqcrystals_kyber768_ref_dec(ss.data(), ct.data(), sk.data());
    else                    rc = pqcrystals_kyber1024_ref_dec(ss.data(), ct.data(), sk.data());
    if (rc != 0) throw std::runtime_error("Kyber decaps failed");
}

// ── pwencrypt ─────────────────────────────────────────────────────────────────

int cmd_pwencrypt(int argc, char* argv[]) {
    // argv[0] = "pwencrypt"
    // Parse: [--level 512|768|1024] [--scrypt-n 20] [--pwfile <file>] <infile> <outfile>
    int level = 768;
    int scrypt_n_log2 = 20;
    std::string infile, outfile, pwfile;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--level") == 0) {
            if (++i >= argc) {
                std::cerr << "Error: --level requires a value\n";
                return 1;
            }
            std::string v = argv[i];
            if (v == "512") level = 512;
            else if (v == "768") level = 768;
            else if (v == "1024") level = 1024;
            else {
                std::cerr << "Error: --level must be 512, 768, or 1024\n";
                return 1;
            }
        } else if (std::strcmp(argv[i], "--scrypt-n") == 0) {
            if (++i >= argc) {
                std::cerr << "Error: --scrypt-n requires a value\n";
                return 1;
            }
            scrypt_n_log2 = std::atoi(argv[i]);
            if (scrypt_n_log2 < 16 || scrypt_n_log2 > 22) {
                std::cerr << "Error: --scrypt-n must be between 16 and 22\n";
                return 1;
            }
        } else if (std::strcmp(argv[i], "--pwfile") == 0) {
            if (++i >= argc) {
                std::cerr << "Error: --pwfile requires a filename\n";
                return 1;
            }
            pwfile = argv[i];
        } else if (argv[i][0] == '-') {
            std::cerr << "Error: unknown option '" << argv[i] << "'\n";
            return 1;
        } else if (infile.empty()) {
            infile = argv[i];
        } else if (outfile.empty()) {
            outfile = argv[i];
        } else {
            std::cerr << "Error: unexpected argument '" << argv[i] << "'\n";
            return 1;
        }
    }

    if (infile.empty() || outfile.empty()) {
        std::cerr << "Usage: pwencrypt [--level 512|768|1024] [--scrypt-n 20] [--pwfile <file>] <infile> <outfile>\n";
        return 1;
    }

    // Read plaintext
    std::vector<uint8_t> plaintext;
    try {
        plaintext = read_file_pw(infile);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }

    // Get password (from file or prompt)
    char passwd[256] = {};
    if (!pwfile.empty()) {
        if (!read_pwfile(pwfile, passwd, (int)sizeof(passwd))) {
            return 1;
        }
    } else if (!prompt_password_confirm(passwd, (int)sizeof(passwd))) {
        std::cerr << "Error: passwords do not match or input failed\n";
        OPENSSL_cleanse(passwd, sizeof(passwd));
        return 1;
    }
    size_t passwd_len = std::strlen(passwd);

    // Generate ephemeral Kyber keypair
    std::vector<uint8_t> pk, sk;
    try {
        kyber_keypair(level, pk, sk);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        OPENSSL_cleanse(passwd, sizeof(passwd));
        return 2;
    }

    // Encapsulate → ct, ss
    std::vector<uint8_t> ct, ss;
    try {
        kyber_encaps(level, pk, ct, ss);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        OPENSSL_cleanse(passwd, sizeof(passwd));
        OPENSSL_cleanse(sk.data(), sk.size());
        return 2;
    }

    // Generate random salt
    uint8_t salt[32];
    if (RAND_bytes(salt, 32) != 1) {
        std::cerr << "Error: RAND_bytes failed\n";
        OPENSSL_cleanse(passwd, sizeof(passwd));
        OPENSSL_cleanse(sk.data(), sk.size());
        OPENSSL_cleanse(ss.data(), ss.size());
        return 2;
    }

    // scrypt: password → wrap_key
    uint8_t wrap_key[32];
    try {
        run_scrypt(passwd, passwd_len, salt, 32,
                   (uint8_t)scrypt_n_log2, 8, 1,
                   wrap_key, 32);
    } catch (const std::exception& e) {
        std::cerr << "Error: scrypt failed: " << e.what() << "\n";
        OPENSSL_cleanse(passwd, sizeof(passwd));
        OPENSSL_cleanse(sk.data(), sk.size());
        OPENSSL_cleanse(ss.data(), ss.size());
        return 2;
    }
    OPENSSL_cleanse(passwd, sizeof(passwd));

    // Wrap sk with wrap_key (AES-256-GCM, no AAD)
    std::vector<uint8_t> wrap_blob;
    try {
        wrap_blob = aes256gcm_encrypt_aad(wrap_key, sk, nullptr, 0);
    } catch (const std::exception& e) {
        std::cerr << "Error: sk wrapping failed: " << e.what() << "\n";
        OPENSSL_cleanse(wrap_key, 32);
        OPENSSL_cleanse(sk.data(), sk.size());
        OPENSSL_cleanse(ss.data(), ss.size());
        return 2;
    }
    OPENSSL_cleanse(wrap_key, 32);
    OPENSSL_cleanse(sk.data(), sk.size());

    // Build 7-byte AAD for data layer
    auto aad = pw_bundle_aad(level);

    // Encrypt plaintext with ss (AES-256-GCM, AAD = first 7 bytes of bundle)
    std::vector<uint8_t> data_blob;
    try {
        data_blob = aes256gcm_encrypt_aad(ss.data(), plaintext, aad.data(), aad.size());
    } catch (const std::exception& e) {
        std::cerr << "Error: data encryption failed: " << e.what() << "\n";
        OPENSSL_cleanse(ss.data(), ss.size());
        return 2;
    }
    OPENSSL_cleanse(ss.data(), ss.size());

    // Assemble bundle
    PwBundle bundle;
    bundle.level = level;
    std::memcpy(bundle.salt, salt, 32);
    bundle.scrypt_n_log2 = (uint8_t)scrypt_n_log2;
    bundle.scrypt_r = 8;
    bundle.scrypt_p = 1;
    bundle.pk = std::move(pk);
    bundle.ct = std::move(ct);
    bundle.wrap_nonce_tag_sk_enc = std::move(wrap_blob);
    bundle.data_nonce_tag_ct = std::move(data_blob);

    // Serialize + armor + write
    try {
        auto wire = pack_pw_bundle(bundle);
        auto armored = armor_pw(wire);
        write_file_pw(outfile, armored);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }

    return 0;
}

// ── pwdecrypt ─────────────────────────────────────────────────────────────────

int cmd_pwdecrypt(int argc, char* argv[]) {
    // argv[0] = "pwdecrypt"
    // Parse: [--pwfile <file>] <infile> <outfile>
    std::string infile, outfile, pwfile;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--pwfile") == 0) {
            if (++i >= argc) {
                std::cerr << "Error: --pwfile requires a filename\n";
                return 1;
            }
            pwfile = argv[i];
        } else if (argv[i][0] == '-') {
            std::cerr << "Error: unknown option '" << argv[i] << "'\n";
            return 1;
        } else if (infile.empty()) {
            infile = argv[i];
        } else if (outfile.empty()) {
            outfile = argv[i];
        } else {
            std::cerr << "Error: unexpected argument '" << argv[i] << "'\n";
            return 1;
        }
    }

    if (infile.empty() || outfile.empty()) {
        std::cerr << "Usage: pwdecrypt [--pwfile <file>] <infile> <outfile>\n";
        return 1;
    }

    // Read and parse bundle
    PwBundle bundle;
    try {
        auto text = read_file_text_pw(infile);
        auto wire = dearmor_pw(text);
        bundle = parse_pw_bundle(wire);
    } catch (const std::exception& e) {
        std::cerr << "Error: failed to parse encrypted file: " << e.what() << "\n";
        return 3;
    }

    // Get password (from file or prompt)
    char passwd[256] = {};
    if (!pwfile.empty()) {
        if (!read_pwfile(pwfile, passwd, (int)sizeof(passwd))) {
            return 1;
        }
    } else if (!prompt_password_once(passwd, (int)sizeof(passwd))) {
        std::cerr << "Error: password input failed\n";
        return 1;
    }
    size_t passwd_len = std::strlen(passwd);

    // scrypt: password → wrap_key
    uint8_t wrap_key[32];
    try {
        run_scrypt(passwd, passwd_len,
                   bundle.salt, 32,
                   bundle.scrypt_n_log2, bundle.scrypt_r, bundle.scrypt_p,
                   wrap_key, 32);
    } catch (const std::exception& e) {
        std::cerr << "decryption failed: incorrect password or corrupted file\n";
        OPENSSL_cleanse(passwd, sizeof(passwd));
        return 2;
    }
    OPENSSL_cleanse(passwd, sizeof(passwd));

    // Unwrap sk
    std::vector<uint8_t> sk;
    try {
        sk = aes256gcm_decrypt_aad(wrap_key, bundle.wrap_nonce_tag_sk_enc, nullptr, 0);
    } catch (const std::exception&) {
        std::cerr << "decryption failed: incorrect password or corrupted file\n";
        OPENSSL_cleanse(wrap_key, 32);
        return 2;
    }
    OPENSSL_cleanse(wrap_key, 32);

    // Validate sk size
    auto sz = kyber_kem_sizes(bundle.level);
    if (sk.size() != sz.sk_bytes) {
        std::cerr << "decryption failed: incorrect password or corrupted file\n";
        OPENSSL_cleanse(sk.data(), sk.size());
        return 2;
    }

    // Kyber decaps: ct + sk → ss
    std::vector<uint8_t> ss;
    try {
        kyber_decaps(bundle.level, sk, bundle.ct, ss);
    } catch (const std::exception&) {
        std::cerr << "decryption failed: incorrect password or corrupted file\n";
        OPENSSL_cleanse(sk.data(), sk.size());
        return 2;
    }
    OPENSSL_cleanse(sk.data(), sk.size());

    // Build AAD and decrypt data
    auto aad = pw_bundle_aad(bundle.level);
    std::vector<uint8_t> plaintext;
    try {
        plaintext = aes256gcm_decrypt_aad(ss.data(), bundle.data_nonce_tag_ct,
                                          aad.data(), aad.size());
    } catch (const std::exception&) {
        std::cerr << "decryption failed: incorrect password or corrupted file\n";
        OPENSSL_cleanse(ss.data(), ss.size());
        return 2;
    }
    OPENSSL_cleanse(ss.data(), ss.size());

    // Write plaintext
    try {
        write_file_pw(outfile, plaintext);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }

    return 0;
}
