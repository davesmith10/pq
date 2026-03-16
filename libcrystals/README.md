# libcrystals

A C++17 static library that consolidates all cryptographic primitives used by the Crystals
tool suite — hybrid post-quantum key encapsulation (Kyber), post-quantum signatures
(Dilithium), classical elliptic-curve operations (X25519, P-256/384/521, Ed25519, ECDSA),
AEAD symmetric encryption, hybrid KDFs, and the tray key-bundle format — into a single
linkable archive.

## Quick start

```cmake
# In your CMakeLists.txt
add_subdirectory(path/to/pq/libcrystals crystals_build)
target_link_libraries(my_target PRIVATE crystals)
```

```cpp
#include <crystals/crystals.hpp>   // umbrella header, pulls in everything
```

Individual component headers can be included on their own (see [API reference](#api-reference)).

## Build

```bash
cmake -S pq/libcrystals -B pq/libcrystals/build \
      -DCMAKE_PREFIX_PATH=/path/to/Crystals/local
cmake --build pq/libcrystals/build -j$(nproc)

# Run the self-test
./pq/libcrystals/build/test_crystals
```

`CMAKE_PREFIX_PATH` must point to the directory where BLAKE3 and oneTBB were installed
(the `Crystals/local/` prefix).  OpenSSL 3 and yaml-cpp must be available via the system
or the same prefix.

### External dependencies

| Dependency | How linked |
|---|---|
| Kyber 512/768/1024 (ref) | statically, via `add_subdirectory(../../kyber/ref)` |
| Dilithium 2/3/5 (ref) | statically, via `add_subdirectory(../../dilithium/ref)` |
| XKCP (SHAKE256, KMAC256) | dynamically — `libXKCP.so` by full path |
| scrypt (Colin Percival) | statically — `.a` archives from `../../scrypt/.libs/` |
| BLAKE3 | dynamically — via `find_package(BLAKE3)` |
| oneTBB | dynamically — via `find_package(TBB)` |
| OpenSSL 3 | via `find_package(OpenSSL)` |
| yaml-cpp | via `find_package(yaml-cpp)` |
| msgpack-c | header-only, `../../msgpack-c/include` |

Binaries that link `crystals` must set RPATH to include the XKCP and TBB shared library
directories (the library's CMakeLists.txt sets `CMAKE_BUILD_RPATH` automatically for the
test binary).

---

## API reference

All public headers live under `include/crystals/`. The umbrella header
`crystals/crystals.hpp` includes them all in dependency order.

---

### Domain model — `crystals/tray.hpp`

A **tray** is a named bundle of cryptographic key slots. Each slot holds one algorithm's
public key and (optionally) secret key.

```cpp
enum class TrayType {
    Level0,       // X25519 + Ed25519  (classical only)
    Level1,       // Kyber512 + Dilithium2  (PQ only)
    Level2_25519, // X25519 + Kyber512 + Ed25519 + Dilithium2  (default)
    Level2,       // P-256 + Kyber512 + ECDSA P-256 + Dilithium2
    Level3,       // P-384 + Kyber768 + ECDSA P-384 + Dilithium3
    Level5,       // P-521 + Kyber1024 + ECDSA P-521 + Dilithium5
};

struct Slot {
    std::string          alg_name; // "X25519", "Kyber768", "ECDSA P-384", "Dilithium3", …
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;       // empty for public-only trays
};

struct Tray {
    int         version      = 1;
    std::string alias;             // human name, e.g. "alice"
    TrayType    tray_type;
    std::string profile_group;     // always "crystals"
    std::string type_str;          // "level0" … "level5"
    std::string id;                // UUID v8 (derived from public keys via BLAKE3)
    bool        is_public    = false;
    std::vector<Slot> slots;
    std::string created;           // ISO 8601 UTC
    std::string expires;           // ISO 8601 UTC (created + 2 years)
};

// Generate a full private tray (all slots have pk + sk).
Tray make_tray(TrayType t, const std::string& alias);

// Derive companion public tray: same UUID, sk cleared, alias becomes "<alias>.pub".
Tray make_public_tray(const Tray& src);
```

**Slot order** by tray type:

| TrayType | slots[0] | slots[1] | slots[2] | slots[3] |
|---|---|---|---|---|
| Level0 | X25519 | Ed25519 | — | — |
| Level1 | Kyber512 | Dilithium2 | — | — |
| Level2_25519 | X25519 | Kyber512 | Ed25519 | Dilithium2 |
| Level2 | P-256 | Kyber512 | ECDSA P-256 | Dilithium2 |
| Level3 | P-384 | Kyber768 | ECDSA P-384 | Dilithium3 |
| Level5 | P-521 | Kyber1024 | ECDSA P-521 | Dilithium5 |

---

### Tray I/O — `crystals/yaml_io.hpp`, `crystals/tray_reader.hpp`, `crystals/tray_pack.hpp`

#### YAML

```cpp
#include <crystals/yaml_io.hpp>

// Serialize a tray to YAML text (binary keys rendered as base64 literal blocks).
std::string emit_tray_yaml(const Tray& tray);
```

#### Auto-detecting load

```cpp
#include <crystals/tray_reader.hpp>

// Load from file. Detects format by first byte:
//   '-' (0x2D) → YAML,  anything else → msgpack.
// Throws std::runtime_error on failure or UUID mismatch.
Tray load_tray(const std::string& path);
```

#### MessagePack

```cpp
#include <crystals/tray_pack.hpp>

namespace tray_mp {
    // In-memory pack/unpack. pk/sk stored as raw bytes (msgpack BIN, not base64).
    std::vector<uint8_t> pack(const Tray& tray);
    Tray                 unpack(const std::vector<uint8_t>& data);

    // File I/O convenience wrappers.
    void pack_to_file(const Tray& tray, const std::string& path);
    Tray unpack_from_file(const std::string& path);
}
```

MessagePack output is approximately 67% the size of the equivalent YAML.

---

### Key generation

#### Classical EC — `crystals/ec_ops.hpp`

```cpp
#include <crystals/ec_ops.hpp>

namespace ec {
    enum class Algorithm { X25519, Ed25519, P256, P384, P521 };

    struct KeyPair {
        std::vector<uint8_t> pk;
        std::vector<uint8_t> sk;
    };

    KeyPair keygen(Algorithm alg);
}
```

#### Kyber (PQ KEM) — `crystals/kyber_ops.hpp`

```cpp
#include <crystals/kyber_ops.hpp>

namespace kyber {
    // level: 512, 768, or 1024
    void keygen(int level, std::vector<uint8_t>& pk, std::vector<uint8_t>& sk);
}
```

#### Dilithium (PQ signatures) — `crystals/dilithium_ops.hpp`

```cpp
#include <crystals/dilithium_ops.hpp>

namespace dilithium {
    // mode: 2, 3, or 5
    void keygen(int mode, std::vector<uint8_t>& pk, std::vector<uint8_t>& sk);
}
```

---

### Key size constants — `crystals/kyber_api.hpp`, `crystals/dilithium_api.hpp`

```cpp
#include <crystals/kyber_api.hpp>

struct KyberSizes    { size_t pk_bytes; size_t sk_bytes; };
struct KyberKEMSizes { size_t pk_bytes; size_t sk_bytes; size_t ct_bytes; size_t ss_bytes; };

KyberSizes    kyber_sizes(int level);      // level: 512, 768, 1024
KyberKEMSizes kyber_kem_sizes(int level);  // ss_bytes is always 32
```

```cpp
#include <crystals/dilithium_api.hpp>

struct DilithiumSizes { size_t pk_bytes; size_t sk_bytes; };

DilithiumSizes dilithium_sizes(int mode);  // mode: 2, 3, 5

// Signature size constants
constexpr size_t DILITHIUM2_SIG_BYTES = 2420;
constexpr size_t DILITHIUM3_SIG_BYTES = 3309;
constexpr size_t DILITHIUM5_SIG_BYTES = 4627;
```

Reference values:

| Algorithm | Public key | Secret key | Ciphertext / Signature |
|---|---|---|---|
| Kyber512 | 800 B | 1632 B | 768 B |
| Kyber768 | 1184 B | 2400 B | 1088 B |
| Kyber1024 | 1568 B | 3168 B | 1568 B |
| Dilithium2 | 1312 B | 2560 B | 2420 B |
| Dilithium3 | 1952 B | 4032 B | 3309 B |
| Dilithium5 | 2592 B | 4896 B | 4627 B |
| X25519 / Ed25519 | 32 B | 32 B | 32 B / 64 B |
| P-256 | 65 B | 32 B | 64 B (ECDSA P1363) |
| P-384 | 97 B | 48 B | 96 B |
| P-521 | 133 B | 66 B | 132 B |

---

### Key encapsulation (KEM)

#### Kyber KEM — `crystals/kyber_kem.hpp`

```cpp
#include <crystals/kyber_kem.hpp>

namespace kyber_kem {
    // Parse "Kyber512" / "Kyber768" / "Kyber1024" → 512 / 768 / 1024.
    int level_from_alg(const std::string& alg_name);

    // Encapsulate: generate ct and shared secret ss against recipient public key pk.
    void encaps(int level,
                const std::vector<uint8_t>& pk,
                std::vector<uint8_t>& ct_out,
                std::vector<uint8_t>& ss_out);

    // Decapsulate: recover ss from ct and recipient secret key sk.
    void decaps(int level,
                const std::vector<uint8_t>& sk,
                const std::vector<uint8_t>& ct,
                std::vector<uint8_t>& ss_out);
}
```

#### EC KEM — `crystals/ec_kem.hpp`

Classical ECDH-based KEM. The ciphertext is the encapsulator's ephemeral public key.

```cpp
#include <crystals/ec_kem.hpp>

namespace ec_kem {
    // Returns true if alg_name is a KEM algorithm ("X25519", "P-256", "P-384", "P-521").
    bool is_classical_kem(const std::string& alg_name);

    // Encapsulate: generate ephemeral keypair, perform ECDH with recipient pk.
    //   ct_out = ephemeral public key bytes
    //   ss_out = ECDH shared secret
    void encaps(const std::string& alg_name,
                const std::vector<uint8_t>& pk,
                std::vector<uint8_t>& ct_out,
                std::vector<uint8_t>& ss_out);

    // Decapsulate: recover ss from ct (ephemeral pk) and recipient sk.
    void decaps(const std::string& alg_name,
                const std::vector<uint8_t>& sk,
                const std::vector<uint8_t>& ct,
                std::vector<uint8_t>& ss_out);
}
```

Supported `alg_name` values: `"X25519"`, `"P-256"`, `"P-384"`, `"P-521"`.

---

### Signatures

#### Dilithium — `crystals/dilithium_sig.hpp`

```cpp
#include <crystals/dilithium_sig.hpp>

namespace dilithium_sig {
    // Returns true if alg_name is "Dilithium2", "Dilithium3", or "Dilithium5".
    bool is_pq_sig(const std::string& alg_name);

    // Parse "Dilithium2/3/5" → 2/3/5.
    int mode_from_alg(const std::string& alg_name);

    // Fixed signature byte size for mode (2420 / 3309 / 4627).
    size_t sig_bytes_for_mode(int mode);

    // Sign msg with sk. sig_out is resized to sig_bytes_for_mode(mode).
    void sign(int mode,
              const std::vector<uint8_t>& sk,
              const std::vector<uint8_t>& msg,
              std::vector<uint8_t>& sig_out);

    // Verify sig over msg with pk. Returns true if valid.
    bool verify(int mode,
                const std::vector<uint8_t>& pk,
                const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& sig);
}
```

#### EC signatures — `crystals/ec_sig.hpp`

Ed25519 uses raw 64-byte signatures. ECDSA uses fixed-size P1363 format (raw r‖s, not DER).

```cpp
#include <crystals/ec_sig.hpp>

namespace ec_sig {
    // Returns true for "Ed25519", "ECDSA P-256", "ECDSA P-384", "ECDSA P-521".
    bool is_classical_sig(const std::string& alg_name);

    // Fixed signature byte size:
    //   Ed25519 → 64, ECDSA P-256 → 64, ECDSA P-384 → 96, ECDSA P-521 → 132
    size_t sig_bytes(const std::string& alg_name);

    void sign(const std::string& alg_name,
              const std::vector<uint8_t>& sk,
              const std::vector<uint8_t>& msg,
              std::vector<uint8_t>& sig_out);

    // Returns true if valid.
    bool verify(const std::string& alg_name,
                const std::vector<uint8_t>& pk,
                const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& sig);
}
```

---

### Hybrid KDFs — `crystals/kdf.hpp`

Header-only; requires XKCP (`SimpleFIPS202.h`, `SP800-185.h`) on the include path.

All functions throw `std::runtime_error` on internal failure.

#### SHAKE256 KDF (OBIWAN encrypt/decrypt)

```cpp
#include <crystals/kdf.hpp>

// Input: len32(ss_cl) || ss_cl || len32(ss_pq) || ss_pq
//      || len32(ct_cl) || ct_cl || len32(ct_pq) || ct_pq
// Output: 32-byte key via SHAKE256.
std::array<uint8_t, 32> derive_key_shake(
    const std::vector<uint8_t>& ss_classical,
    const std::vector<uint8_t>& ss_pq,
    const std::vector<uint8_t>& ct_classical,
    const std::vector<uint8_t>& ct_pq);
```

#### KMAC256 KDF (OBIWAN encrypt/decrypt, alternative)

```cpp
// KMAC256(key=ss_cl, msg=len32(ss_pq)||ss_pq||len32(ct_cl)||ct_cl||len32(ct_pq)||ct_pq,
//         custom="hybrid-kem-file-encryption-v1", outlen=256 bits)
std::array<uint8_t, 32> derive_key_kmac(
    const std::vector<uint8_t>& ss_classical,
    const std::vector<uint8_t>& ss_pq,
    const std::vector<uint8_t>& ct_classical,
    const std::vector<uint8_t>& ct_pq);
```

#### HYKE KDF (sign/verify commands)

```cpp
// KMAC256(key=ss_cl, msg=ss_pq||ct_cl||ct_pq||salt,
//         custom="obi-wan-hybrid-sig-v1", outlen=256 bits)
// Note: no len32 prefixes — raw concatenation.
std::array<uint8_t, 32> derive_key_hyke(
    const std::vector<uint8_t>& ss_classical,
    const std::vector<uint8_t>& ss_pq,
    const std::vector<uint8_t>& ct_classical,
    const std::vector<uint8_t>& ct_pq,
    const uint8_t salt[32]);

// Key-substitution prevention context binding.
// KMAC256(key=pk_cl, msg=pk_pq||"obi-wan-hybrid-sig-v1", outlen=512 bits) → 64 bytes.
std::vector<uint8_t> compute_hyke_ctx(
    const std::vector<uint8_t>& pk_classical,
    const std::vector<uint8_t>& pk_pq);
```

---

### Symmetric AEAD — `crystals/symmetric.hpp`

Header-only. All functions use a random 12-byte nonce and output/expect the layout:
`nonce(12) || tag(16) || ciphertext(N)`. Decryption throws `std::runtime_error` on
authentication failure.

```cpp
#include <crystals/symmetric.hpp>

// AES-256-GCM (no AAD)
std::vector<uint8_t> aes256gcm_encrypt(const uint8_t key[32],
                                        const std::vector<uint8_t>& plaintext);
std::vector<uint8_t> aes256gcm_decrypt(const uint8_t key[32],
                                        const std::vector<uint8_t>& nonce_tag_ct);

// AES-256-GCM with additional authenticated data
std::vector<uint8_t> aes256gcm_encrypt_aad(const uint8_t key[32],
                                             const std::vector<uint8_t>& plaintext,
                                             const uint8_t* aad, size_t aad_len);
std::vector<uint8_t> aes256gcm_decrypt_aad(const uint8_t key[32],
                                             const std::vector<uint8_t>& nonce_tag_ct,
                                             const uint8_t* aad, size_t aad_len);

// ChaCha20-Poly1305 (no AAD variant)
std::vector<uint8_t> chacha20poly1305_encrypt(const uint8_t key[32],
                                               const std::vector<uint8_t>& plaintext);
std::vector<uint8_t> chacha20poly1305_decrypt(const uint8_t key[32],
                                               const std::vector<uint8_t>& nonce_tag_ct);
```

---

### Wire formats

#### OBIWAN encrypted file — `crystals/armor.hpp`

```
Wire layout:
  "OBIWAN01"    8 bytes  magic
  KDF           1 byte   0=SHAKE256, 1=KMAC256
  Cipher        1 byte   0=AES-256-GCM, 1=ChaCha20-Poly1305
  ct_cl_len     4 bytes  big-endian uint32
  ct_classical  N bytes
  ct_pq_len     4 bytes
  ct_pq         M bytes
  payload       nonce(12) || tag(16) || ciphertext
```

```cpp
#include <crystals/armor.hpp>

enum class KDFAlg    : uint8_t { SHAKE256 = 0, KMAC256 = 1 };
enum class CipherAlg : uint8_t { AES256GCM = 0, ChaCha20Poly1305 = 1 };

struct WireHeader {
    KDFAlg               kdf;
    CipherAlg            cipher;
    std::vector<uint8_t> ct_classical;
    std::vector<uint8_t> ct_pq;
};

// Pack header + payload into wire bytes, then base64-armor between
// "-----BEGIN OBIWAN ENCRYPTED FILE-----" markers.
std::string armor_pack(const WireHeader& hdr, const std::vector<uint8_t>& payload);

// Dearmor and unpack. Throws std::runtime_error on malformed input.
WireHeader armor_unpack(const std::string& armored, std::vector<uint8_t>& payload_out);
```

#### HYKE signed file — `crystals/hyke_format.hpp`

```
Wire layout:
  "HYKE"         4 bytes magic
  version        2 bytes 0x0001
  tray_id        1 byte  0x01=Level2_25519 … 0x04=Level5
  flags          1 byte  0x00 (reserved)
  header_len     4 bytes total header size
  payload_len    4 bytes
  tray_uuid      16 bytes (binary)
  salt           32 bytes
  ct_cl_len      4 bytes
  ct_pq_len      4 bytes
  sig_cl_len     4 bytes
  sig_pq_len     4 bytes
  ct_classical   N bytes
  ct_pq          M bytes
  sig_classical  P bytes
  sig_pq         Q bytes
  payload        nonce(12) || tag(16) || ciphertext
```

```cpp
#include <crystals/hyke_format.hpp>

struct HykeHeader {
    uint8_t              tray_id = 0;
    uint8_t              tray_uuid[16] = {};
    uint8_t              salt[32] = {};
    std::vector<uint8_t> ct_classical;
    std::vector<uint8_t> ct_pq;
    std::vector<uint8_t> sig_classical;
    std::vector<uint8_t> sig_pq;
};

// Build the partial header (offsets 0 … 80+N+M) used as the signed region.
std::vector<uint8_t> hyke_partial_header(const HykeHeader& hdr,
                                          uint32_t payload_len,
                                          uint32_t sig_cl_len,
                                          uint32_t sig_pq_len);

// Pack complete wire bytes (hdr.sig_classical and hdr.sig_pq must be filled first).
std::vector<uint8_t> hyke_pack(const HykeHeader& hdr, const std::vector<uint8_t>& payload);

// Unpack wire bytes into header + payload. Throws on malformed input.
HykeHeader hyke_unpack(const std::vector<uint8_t>& wire, std::vector<uint8_t>& payload_out);

// Base64 armor between "-----BEGIN HYKE SIGNED FILE-----" markers.
std::string         hyke_armor  (const std::vector<uint8_t>& wire);
std::vector<uint8_t> hyke_dearmor(const std::string& text);

// Helper conversions
uint8_t  tray_id_byte    (TrayType t);
TrayType tray_type_from_id(uint8_t id);
void     parse_uuid      (const std::string& uuid_str, uint8_t uuid_bytes[16]);
```

The signed region committed to by both signatures is:
`ctx(64) || partial_header(80+N+M bytes) || encrypted_payload`
where `ctx = compute_hyke_ctx(pk_classical, pk_pq)` (see KDF section).

#### PWENC password-encrypted file — `crystals/pw_format.hpp`

Ephemeral Kyber KEM + scrypt-derived key-wrapping. Two AES-256-GCM layers; AAD for
both is the 7-byte prefix `"OBWE" || 0x01 || level_be16`.

```cpp
#include <crystals/pw_format.hpp>

struct PwBundle {
    int     level;                            // 512, 768, or 1024
    uint8_t salt[32];
    uint8_t scrypt_n_log2;                    // N = 2^scrypt_n_log2
    uint8_t scrypt_r;
    uint8_t scrypt_p;
    std::vector<uint8_t> pk;                  // ephemeral Kyber pk
    std::vector<uint8_t> ct;                  // ephemeral Kyber ciphertext
    std::vector<uint8_t> wrap_nonce_tag_sk_enc; // 12+16+sk_size blob (key-wrap layer)
    std::vector<uint8_t> data_nonce_tag_ct;     // 12+16+M blob (data layer)
};

// Returns the 7-byte AAD: magic(4) || version(1) || level_be16(2)
std::vector<uint8_t> pw_bundle_aad(int level);

// Serialize/parse the wire format.
std::vector<uint8_t> pack_pw_bundle  (const PwBundle& b);
PwBundle             parse_pw_bundle (const std::vector<uint8_t>& wire);

// Base64 armor between "-----BEGIN OBIWAN PW ENCRYPTED FILE-----" markers.
std::string          armor_pw  (const std::vector<uint8_t>& wire);
std::vector<uint8_t> dearmor_pw(const std::string& text);
```

#### Token wire format — `crystals/token_format.hpp`, `crystals/token_cmd.hpp`

Single-use bearer token: data payload signed with ECDSA P-256 (requires a `level2` tray).

```
Wire layout:
  "obi-wan\0"   8 bytes  magic
  version       2 bytes  0x01 0x00
  TLV 0x01      data (1–256 bytes)
  TLV 0x02      issued_at  (8 bytes int64 BE Unix epoch)
  TLV 0x03      expires_at (8 bytes int64 BE Unix epoch)
  TLV 0x04      tray_uuid  (16 bytes binary UUID)
  TLV 0x05      algorithm  (1 byte: 0x03 = ECDSA-P256-SHA256 — only valid value; 0x01/0x02 reserved)
  TLV 0x06      token_uuid (16 bytes random UUID v4)
  SIG_LEN       4 bytes BE uint32 (= 64 for ECDSA P-256)
  signature     SIG_LEN bytes
```

Signed region: `magic(8) || version(2) || TLV[0x01..0x06]` (no sig trailer).

```cpp
#include <crystals/token_format.hpp>

struct Token {
    std::vector<uint8_t> data;
    int64_t issued_at  = 0;
    int64_t expires_at = 0;
    uint8_t tray_uuid[16]  = {};
    uint8_t token_uuid[16] = {};
    uint8_t algorithm  = kTokenAlgECDSAP256;  // 0x03
    std::vector<uint8_t> signature;
};

// Compute the signed region (magic + version + 6 TLVs, no sig trailer).
std::vector<uint8_t> token_canonical_bytes(const Token& tok);

// Serialize to full wire bytes (canonical + SIG_LEN + signature).
std::vector<uint8_t> token_pack(const Token& tok);

// Deserialize wire bytes. Throws std::runtime_error on bad magic, ordering,
// invalid algorithm, issued_at > expires_at, or wrong SIG_LEN.
Token token_unpack(const std::vector<uint8_t>& wire);

// Armor: base64(wire) + '\n'
std::string          token_armor  (const std::vector<uint8_t>& wire);

// Dearmor: strips whitespace/newlines, then base64-decodes.
std::vector<uint8_t> token_dearmor(const std::string& text);
```

CLI-level commands (require a loaded tray and OpenSSL):

```cpp
#include <crystals/token_cmd.hpp>

// Generate a signed token with data_str payload and ttl_secs lifetime.
// Requires a level2 tray with an ECDSA P-256 sk. Writes armored token to stdout.
void cmd_gentok(const std::string& tray_path, const std::string& data_str, int64_t ttl_secs);

// Validate an armored token: checks time bounds, UUID match, and ECDSA P-256 signature.
// Requires a level2 tray. Writes the data payload to stdout on success. Exits non-zero on any failure.
void cmd_valtok(const std::string& tray_path, const std::string& token_file);
```

---

### Utilities

#### Base64 — `crystals/base64.hpp`

```cpp
#include <crystals/base64.hpp>

std::string          base64_encode(const uint8_t* data, size_t len);
std::vector<uint8_t> base64_decode(const std::string& encoded);
```

---

## Error handling

All functions that can fail throw `std::runtime_error` (or a subclass). Functions that
return `bool` (signature verify) do **not** throw — they return `false` on a bad
signature and throw only on internal errors (e.g. OpenSSL API failure).

Invalid integer arguments (bad Kyber level, Dilithium mode, unsupported `alg_name`) throw
`std::invalid_argument`.

---

## Running the tests

```bash
cmake --build pq/libcrystals/build -j$(nproc)
./pq/libcrystals/build/test_crystals
```

The test binary exercises all 11 functional areas: keygen for all 6 tray types, YAML and
msgpack round-trips, UUID tamper detection, Kyber KEM at all 3 levels, EC KEM at all 4
curves, Dilithium sign/verify at all 3 modes, EC sign/verify at all 4 algorithms, OBIWAN
armor pack/unpack, AES-256-GCM and ChaCha20-Poly1305 (with and without AAD), and PWENC
wire format at all 3 Kyber levels.
