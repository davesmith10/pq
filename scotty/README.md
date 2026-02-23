# scotty — Dilithium Signature Swiss Army Knife

`scotty` is a command-line tool for generating, signing, and verifying post-quantum digital
signatures using the **CRYSTALS-Dilithium** (ML-DSA) algorithm. It supports all three NIST
security levels and both the portable reference and AVX2-optimised implementations.

It is a companion to [`luke`](../luke/), which handles Kyber KEM operations. Together they
provide a complete post-quantum "swiss-army knife" style toolkit built on the
[pqcrystals/dilithium](https://github.com/pqcrystals/dilithium) reference library.

---

## Security levels

| Flag  | NIST name  | Public key | Secret key | Signature | NIST level |
|-------|------------|------------|------------|-----------|------------|
| `--d2` | ML-DSA-44 | 1312 bytes | 2560 bytes | 2420 bytes | II  |
| `--d3` | ML-DSA-65 | 1952 bytes | 4032 bytes | 3309 bytes | III |
| `--d5` | ML-DSA-87 | 2592 bytes | 4896 bytes | 4627 bytes | V   |

**Default:** `--d3` (ML-DSA-65 / Dilithium3).

---

## Commands

```
scotty keygen  [--d2|--d3|--d5] [--impl ref|avx2] --pk <file> --sk <file>
scotty sign    [--d2|--d3|--d5] [--impl ref|avx2] --sk <file> --msg <file> --sig <file> [--ctx <str>]
scotty verify  [--d2|--d3|--d5] [--impl ref|avx2] --pk <file> --msg <file> --sig <file> [--ctx <str>]
```

### keygen

Generates a Dilithium keypair and writes both keys as PEM-armored files.

```
--pk <file>   Output: public key
--sk <file>   Output: secret key
```

### sign

Signs the contents of `--msg` using the secret key and writes the detached signature.

```
--sk  <file>    Input:  secret key (PEM)
--msg <file>    Input:  message to sign (arbitrary binary)
--sig <file>    Output: detached signature (PEM)
--ctx <string>  Optional: signing context string (default: "scotty:signing:v1")
```

### verify

Verifies a detached signature against a message and public key.

```
--pk  <file>    Input: public key (PEM)
--msg <file>    Input: message that was signed
--sig <file>    Input: detached signature (PEM)
--ctx <string>  Optional: signing context string (must match the one used during sign)
```

Prints `Signature valid.` or `Signature INVALID.` to stdout and exits accordingly.

---

## Options summary

| Option | Default | Description |
|--------|---------|-------------|
| `--d2` | — | Use Dilithium2 (ML-DSA-44) |
| `--d3` | **yes** | Use Dilithium3 (ML-DSA-65) |
| `--d5` | — | Use Dilithium5 (ML-DSA-87) |
| `--impl ref` | **yes** | Use portable C reference implementation |
| `--impl avx2` | — | Use AVX2-optimised implementation |
| `--pk <file>` | — | Public key file path |
| `--sk <file>` | — | Secret key file path |
| `--msg <file>` | — | Message file path |
| `--sig <file>` | — | Signature file path |
| `--ctx <str>` | `scotty:signing:v1` | Signing context (ML-DSA context string) |

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (or `verify`: signature is valid) |
| 1 | Usage error (bad arguments) |
| 2 | Crypto error (or `verify`: signature is **invalid**) |
| 3 | I/O error (missing file, wrong PEM header, etc.) |

---

## Output format

Keys and signatures are stored as **PEM-like Base64 ASCII armor**, using headers that
include the security level to prevent accidental cross-level misuse:

```
-----BEGIN DILITHIUM3 PUBLIC KEY-----
...base64 encoded data...
-----END DILITHIUM3 PUBLIC KEY-----
```

Header types:
- `DILITHIUM2 PUBLIC KEY` / `DILITHIUM3 PUBLIC KEY` / `DILITHIUM5 PUBLIC KEY`
- `DILITHIUM2 SECRET KEY` / `DILITHIUM3 SECRET KEY` / `DILITHIUM5 SECRET KEY`
- `DILITHIUM2 SIGNATURE` / `DILITHIUM3 SIGNATURE` / `DILITHIUM5 SIGNATURE`

If you attempt to verify a signature file whose header says `DILITHIUM2` while passing
`--d3`, scotty reports an I/O error (exit 3) rather than producing a silent wrong result.

---

## Signing context

The `--ctx` parameter maps directly to the ML-DSA **context string** (a domain-separation
input to the signing algorithm). Two signatures over the same message are
cryptographically distinct if they were produced with different context strings, and
verification will fail if the context strings don't match.

The default context `scotty:signing:v1` is used when `--ctx` is omitted on both `sign`
and `verify`. You can use any string up to the library's limit; an empty string (`""`) is
valid.

Practical use: set `--ctx` to an application name or protocol version to prevent
signatures issued for one purpose from being reused in another.

---

## Build

### Prerequisites

A C++17 compiler, CMake ≥ 3.15, and the Dilithium shared libraries.

**Step 1 — build the Dilithium shared libraries:**

```bash
cd ../dilithium/ref  && make shared
cd ../dilithium/avx2 && make shared
```

This produces:
```
dilithium/ref/libpqcrystals_dilithium{2,3,5}_ref.so
dilithium/ref/libpqcrystals_fips202_ref.so
dilithium/avx2/libpqcrystals_dilithium{2,3,5}_avx2.so
dilithium/avx2/libpqcrystals_fips202_avx2.so
dilithium/avx2/libpqcrystals_fips202x4_avx2.so
```

**Step 2 — build scotty:**

```bash
mkdir build && cd build
cmake ..
make
```

The binary is `build/scotty`. No installation step is required; RPATH is baked in so the
binary locates all `.so` files relative to the source tree at runtime.

### Build system notes

- All nine `.so` files are linked by **full path** in `CMakeLists.txt`. This avoids any
  `-l` name collision between the ref and avx2 directories.
- `randombytes.c` from `dilithium/ref/` is compiled directly into the binary because the
  Dilithium `.so` files leave `randombytes` as an undefined external symbol.
- `CMAKE_INSTALL_RPATH` is set to both `dilithium/ref/` and `dilithium/avx2/` so the
  binary runs without setting `LD_LIBRARY_PATH`.

---

## Usage examples

### Basic round-trip (defaults: Dilithium3, ref impl)

```bash
# Generate a keypair
scotty keygen --pk alice.pub --sk alice.priv

# Sign a file
scotty sign --sk alice.priv --msg document.pdf --sig document.sig

# Verify
scotty verify --pk alice.pub --msg document.pdf --sig document.sig
# → Signature valid.
```

### Higher security level with AVX2

```bash
scotty keygen --d5 --impl avx2 --pk alice.pub --sk alice.priv
scotty sign   --d5 --impl avx2 --sk alice.priv --msg data.bin --sig data.sig
scotty verify --d5 --impl avx2 --pk alice.pub  --msg data.bin --sig data.sig
```

### Application-specific context

```bash
# Signer and verifier must agree on the context string
scotty sign   --sk alice.priv --msg payload.json --sig payload.sig --ctx "myapp:auth:v2"
scotty verify --pk alice.pub  --msg payload.json --sig payload.sig --ctx "myapp:auth:v2"
```

### Scripted batch verification (exit code check)

```bash
scotty verify --pk alice.pub --msg file.bin --sig file.sig
if [ $? -eq 0 ]; then
    echo "OK, proceeding"
else
    echo "Verification failed ($?)" >&2
    exit 1
fi
```

---

## Source layout

```
scotty/
├── CMakeLists.txt       Build definition
├── main.cpp             CLI argument parsing and command dispatch
├── dilithium_api.hpp    extern "C" declarations for all 12 library functions
│                        + DilithiumParams struct with function pointers
│                        + make_params() factory
├── dilithium_ops.hpp    keygen / sign / verify wrapper declarations
├── dilithium_ops.cpp    keygen / sign / verify wrapper implementations
├── pem_io.hpp           PEM armor read/write interface
├── pem_io.cpp           PEM armor read/write implementation
├── base64.hpp           Base64 encode/decode interface
└── base64.cpp           Base64 encode/decode implementation
```

---

## Keys are not interchangeable with luke / Kyber

Dilithium (used by `scotty`) and Kyber (used by [`luke`](../luke/)) are both built on
**module lattice** mathematics — specifically, both derive their security from variants of
the Module Learning With Errors (MLWE) problem — but they are distinct algorithms with
incompatible key structures and completely different purposes:

| Property | Dilithium (scotty) | Kyber (luke) |
|----------|--------------------|--------------|
| Purpose | Digital signatures | Key encapsulation (KEM) |
| Hard problem | Module-LWE + Module-SIS (signing + verification) | Module-LWE (decryption hardness) |
| Secret key role | Produce a signature | Decrypt the shared secret |
| Public key role | Verify a signature | Encrypt a shared secret |
| Key sizes (level 3) | pk: 1952 B, sk: 4032 B | pk: 1184 B, sk: 2400 B |

A Dilithium secret key **cannot** be used in a KEM, and a Kyber secret key **cannot** be
used to sign a message. The internal polynomial representations, noise distributions, and
key-derivation procedures differ between the two algorithms. Passing a Kyber key file to
`scotty` (or vice versa) will be caught immediately by the PEM header check (`DILITHIUM3`
vs `KYBER768`), but even if that check were bypassed the raw bytes would be structurally
meaningless to the other algorithm.

If you need both confidentiality and authentication, generate **separate** Dilithium and
Kyber keypairs and use `scotty` for signing and `luke` for key exchange.

---

## Relationship to ML-DSA / FIPS 204

Dilithium3 was standardised as **ML-DSA-65** in NIST FIPS 204 (August 2024). The
underlying algorithm is identical; only the naming changed. `scotty` uses the original
`pqcrystals` library naming in PEM headers (`DILITHIUM2/3/5`) rather than the FIPS names
(`ML-DSA-44/65/87`) to stay consistent with the library's own identifiers.

The `--ctx` parameter corresponds directly to the **ctx** input defined in FIPS 204
§5.2 (ML-DSA.Sign) and §3.3 (ML-DSA.Verify). The default context `"scotty:signing:v1"`
is a non-empty domain separator; pass `--ctx ""` to use an empty context if your protocol
requires it.
