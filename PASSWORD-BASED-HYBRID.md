# Password-Based Hybrid Encryption — Implementation Plan

## Goal

Add `encrypt` and `decrypt` commands to `luke` that implement a complete
password-based hybrid encryption scheme using Kyber as the KEM and AES-256-GCM
as the symmetric cipher.

The user never stores or transmits the secret key. It is reconstructed on
demand from the password via `hashpass → seed → keygen --seed`.

---

## Scheme

```
ENCRYPT
───────
password ──→ hashpass ──→ seed (32 bytes)
seed ────→ keygen_derand(seed) ──→ (pk, sk)   sk is ephemeral, never saved
pk ──────→ encaps(pk) ─────────→ (ct, ss)     ss = 32-byte session key
ss ──────→ AES-256-GCM(nonce, plaintext) ────→ ciphertext + tag

bundle written to disk:
  magic(4) | version(1) | level(2) | ct(N) | nonce(12) | tag(16) | ciphertext(M)

DECRYPT
───────
password ──→ hashpass ──→ same seed
seed ────→ keygen_derand(seed) ──→ same (pk, sk)
sk + ct ─→ decaps(sk, ct) ────→ same ss
ss ──────→ AES-256-GCM-decrypt(nonce, ciphertext, tag) ──→ plaintext
```

The Kyber ciphertext `ct` inside the bundle is what a post-quantum adversary
must break to recover `ss` without knowing the password.

---

## Bundle Format

All integers are little-endian.

| Field       | Size (bytes)          | Value                              |
|-------------|-----------------------|------------------------------------|
| magic       | 4                     | `L` `U` `K` `B`                   |
| version     | 1                     | `0x01`                             |
| level       | 2                     | 512 / 768 / 1024                   |
| ct          | 768 / 1088 / 1568     | Kyber KEM ciphertext               |
| nonce       | 12                    | AES-GCM nonce (random per encrypt) |
| tag         | 16                    | AES-GCM authentication tag         |
| ciphertext  | M (rest of file)      | AES-256-GCM encrypted plaintext    |

Total overhead vs plaintext: 4+1+2+ct_bytes+12+16 bytes.
For Kyber768 that is 1123 bytes of overhead.

---

## Files to Create

### `luke/src/aes_gcm.hpp`
Header-only AES-256-GCM using OpenSSL EVP (no deprecated APIs).

```cpp
// Returns nonce (12 bytes) + tag (16 bytes) + ciphertext
std::vector<uint8_t> aes256gcm_encrypt(
    const uint8_t key[32],
    const std::vector<uint8_t>& plaintext);

// Returns plaintext; throws on auth failure
std::vector<uint8_t> aes256gcm_decrypt(
    const uint8_t key[32],
    const std::vector<uint8_t>& nonce_tag_ct);  // nonce(12)+tag(16)+ct
```

Internally uses `EVP_EncryptInit_ex` / `EVP_DecryptInit_ex` with
`EVP_aes_256_gcm()`. Random nonce via `RAND_bytes`.

### `luke/src/bundle.hpp`
Read/write the bundle format described above.

```cpp
void     bundle_write(const std::string& path, int level,
                      const std::vector<uint8_t>& ct,
                      const std::vector<uint8_t>& nonce_tag_ciphertext);

struct   BundleHeader { int level; std::vector<uint8_t> ct; };
BundleHeader bundle_read_header(std::ifstream& f);
std::vector<uint8_t> bundle_read_body(std::ifstream& f);
```

---

## Files to Modify

### `luke/src/main.cpp`
Add two commands and two new `--in` / `--out` args to `Args`.

**`encrypt` command** (`--seed` or `--pk`, plus `--in` and `--out`):
1. If `--seed`: call `keygen_derand(seed)` → `(pk, sk)`, discard `sk`.
   If `--pk`: load pk from file.
2. Call `encaps(pk)` → `(ct, ss)`.
3. Read plaintext from `--in`.
4. `aes256gcm_encrypt(ss, plaintext)` → `nonce_tag_ct`.
5. `bundle_write(--out, level, ct, nonce_tag_ct)`.

**`decrypt` command** (`--seed` or `--sk`, plus `--in` and `--out`):
1. If `--seed`: call `keygen_derand(seed)` → `(pk, sk)`.
   If `--sk`: load sk from file.
2. Open `--in`, `bundle_read_header` → `ct` + `level`.
3. `decaps(sk, ct)` → `ss`.
4. `bundle_read_body` → `nonce_tag_ct`.
5. `aes256gcm_decrypt(ss, nonce_tag_ct)` → `plaintext`.
6. Write plaintext to `--out`.

Usage strings added:
```
  encrypt   Encrypt a file (KEM + AES-256-GCM)
  decrypt   Decrypt a bundle file
  --in  <file>   Input plaintext / bundle file
  --out <file>   Output bundle / plaintext file
```

### `luke/CMakeLists.txt`
Add OpenSSL to the link:
```cmake
find_package(OpenSSL REQUIRED)
target_link_libraries(luke PRIVATE ... OpenSSL::SSL OpenSSL::Crypto)
```

---

## Verification

```bash
# Build
cd luke/build && cmake .. && make

# Password-based round-trip
SEED=$(cd ../../misc && printf 'Xk9#mQ2$vLpZ7!nRwA4@BcD' | ./hashpass)
echo "The quick brown fox" > plain.txt

./luke keygen --seed $SEED --pk tmp.pk --sk tmp.sk   # confirm seed→keypair

./luke encrypt --seed $SEED --in plain.txt --out encrypted.lukb
./luke decrypt --seed $SEED --in encrypted.lukb --out decrypted.txt
diff plain.txt decrypted.txt   # must be identical

# Key-file based round-trip (traditional KEM flow)
./luke keygen --pk rsa.pk --sk rsa.sk
./luke encrypt --pk rsa.pk --in plain.txt --out encrypted2.lukb
./luke decrypt --sk rsa.sk --in encrypted2.lukb --out decrypted2.txt
diff plain.txt decrypted2.txt

# Wrong password → decaps produces wrong ss → AES-GCM auth tag fails → error
BAD_SEED=$(cd ../../misc && printf 'WrongPass#0987654321ABc' | ./hashpass)
./luke decrypt --seed $BAD_SEED --in encrypted.lukb --out should_fail.txt
# expect: "Crypto error: AES-GCM decryption failed (authentication)"
```
