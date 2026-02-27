# pq — Post-Quantum Crypto Tools

C++17 CLI tools and libraries for Kyber KEM, Dilithium signatures, and hybrid
PQ+classical key management. Built against the CRYSTALS reference and AVX2
implementations from [pq-crystals](https://github.com/pq-crystals).

## Tools

### luke — Kyber KEM

Key encapsulation using CRYSTALS-Kyber (ML-KEM). Supports Kyber512, Kyber768,
and Kyber1024 with both reference and AVX2 implementations.

```
luke <keygen|encaps|decaps> [--level 512|768|1024] [--impl ref|avx2]
     --pk <file> --sk <file> --kem <file> --ss <file>
```

Also supports `encrypt`/`decrypt` commands (Kyber KEM + AES-256-GCM) for
arbitrary file encryption with `.lukb` binary bundles.

Output uses PEM-style ASCII armor: `-----BEGIN KYBER768 PUBLIC KEY-----`

### geordi — Dilithium Signatures

Digital signatures using CRYSTALS-Dilithium (ML-DSA). Supports Dilithium2,
Dilithium3, and Dilithium5 with both reference and AVX2 implementations.

```
geordi <keygen|sign|verify> [--d2|--d3|--d5] [--impl ref|avx2]
       --pk <file> --sk <file> --msg <file> --sig <file> [--ctx <string>]
```

Default: Dilithium3 / ref impl / context string `"geordi:signing:v1"`

Output uses PEM-style ASCII armor: `-----BEGIN DILITHIUM3 PUBLIC KEY-----`

### scotty — Hybrid Tray Keygen

Generates named **hybrid trays** — bundles of paired PQ+classical key slots
covering both KEM and signature roles.

```
scotty keygen [--tray level2|level2nist|level3nist|level5nist]
              --alias <name>
              [--out <file>] [--summary] [--classiconly|--pqonly]
```

| Tray        | KEM-classic | KEM-PQ    | Sig-classic  | Sig-PQ     |
|-------------|-------------|-----------|--------------|------------|
| `level2`    | X25519      | Kyber512  | Ed25519      | Dilithium2 |
| `level2nist`| P-256       | Kyber512  | ECDSA P-256  | Dilithium2 |
| `level3nist`| P-384       | Kyber768  | ECDSA P-384  | Dilithium3 |
| `level5nist`| P-521       | Kyber1024 | ECDSA P-521  | Dilithium5 |

Default tray: `level2`.

**Output modes:**
- Default (no flags): YAML with literal block scalar base64 to stdout
- `--out <file>`: write compact binary MessagePack to `<file>` (~67% of YAML size)
- `--summary`: print a human-readable one-line summary to stdout

### obi-wan — Hybrid KEM File Encryption

Encrypts arbitrary files using both KEM slots from a scotty tray (classical +
post-quantum), combining their shared secrets with a KDF, then encrypting with
an AEAD cipher. Accepts both YAML and binary msgpack trays.

```
obi-wan encrypt --tray <file> [--kdf SHAKE|KMAC] [--cipher AES-256-GCM|ChaCha20] <target-file>
obi-wan decrypt --tray <file> <target-file>
```

- `--kdf`: Key derivation function — `SHAKE` (SHAKE256, default) or `KMAC` (KMAC256)
- `--cipher`: Symmetric AEAD — `AES-256-GCM` (default) or `ChaCha20` (ChaCha20-Poly1305)
- `--tray`: accepts both YAML (`.tray` stdout) and binary msgpack (`.tray` file) — auto-detected
- encrypt writes base64 ASCII armor to stdout; KDF/cipher stored in wire header, auto-detected on decrypt

Output armor:
```
-----BEGIN OBIWAN ENCRYPTED FILE-----
<base64 at 64 chars/line>
-----END OBIWAN ENCRYPTED FILE-----
```

Wire format (binary before base64): `"OBIWAN01"` magic (8B) + KDF byte + cipher byte +
`len32 + CT_classical` + `len32 + CT_pq` + `nonce(12) || tag(16) || ciphertext`

Both KEM shared secrets are combined via the KDF before deriving the symmetric key,
so security requires breaking **both** the classical and post-quantum KEMs.

### msgpack — Tray Binary Encoding

Static library (`libtraymsgpack.a`) and shared implementation used by scotty.
Converts `Tray` objects to and from compact MessagePack binary. YAML is the
canonical human-readable form; msgpack is the compact deployment artifact.

The `tray_pack` module is compiled directly into `scotty` (no separate library
step needed to use `--out`). Use the standalone library for other consumers:

```cpp
#include "tray_pack.hpp"
std::vector<uint8_t> bytes = tray_mp::pack(tray);
Tray t = tray_mp::unpack(bytes);
tray_mp::pack_to_file(tray, "alice.tray");
Tray t2 = tray_mp::unpack_from_file("alice.tray");
```

Wire format: top-level msgpack map with short keys (`v`, `a`, `t`, `id`, `cr`,
`ex`, `sl`); pk/sk stored as raw bytes (BIN), not base64. Achieves ~67% of YAML
file size across all tray types.

**Dependency**: requires `msgpack-c` header-only library vendored at
`Crystals/msgpack-c/`. Do not remove this directory.

## Build

**Prerequisites**: CMake ≥ 3.15, GCC/Clang with C++17, OpenSSL 3, yaml-cpp.
Crypto `.so` files must be built first (one-time):

```bash
cd kyber/ref  && make shared
cd kyber/avx2 && make shared
cd dilithium/ref  && make shared
cd dilithium/avx2 && make shared
```

**Build individual tools** (from the `Crystals/` root):

```bash
cmake -S pq/luke      -B pq/luke/build      && cmake --build pq/luke/build      -j$(nproc)
cmake -S pq/geordi/src -B pq/geordi/build   && cmake --build pq/geordi/build    -j$(nproc)
cmake -S pq/scotty    -B pq/scotty/build    && cmake --build pq/scotty/build    -j$(nproc)
cmake -S pq/obi-wan   -B pq/obi-wan/build   && cmake --build pq/obi-wan/build   -j$(nproc)
cmake -S pq/msgpack   -B pq/msgpack/build   && cmake --build pq/msgpack/build   -j$(nproc)
```

**Build self-contained distribution** (copies binaries + `.so` files to `pq/dist/`):

```bash
cd pq && bash package.sh          # incremental
cd pq && bash package.sh --clean  # clean rebuild
```

## Exit Codes

All tools use the same exit code convention:

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | Usage / argument error |
| `2`  | Crypto failure (decaps mismatch, invalid signature) |
| `3`  | I/O error (file not found, wrong PEM header level) |

## Repository Layout

```
Crystals/
├── kyber/ref/          — Kyber reference implementation + .so files
├── kyber/avx2/         — Kyber AVX2 implementation + .so files
├── dilithium/ref/      — Dilithium reference implementation + .so files
├── dilithium/avx2/     — Dilithium AVX2 implementation + .so files
├── msgpack-c/          — msgpack-c header-only library (vendored)
├── XKCP/               — eXtended Keccak Code Package (SHAKE256, KMAC256)
└── pq/                 — Main project (git root)
    ├── include/        — Shared headers (tray.hpp domain model)
    ├── luke/           — Kyber KEM CLI tool
    ├── geordi/src/     — Dilithium signature CLI tool
    ├── scotty/         — Hybrid PQ+classical tray keygen tool
    ├── obi-wan/        — Hybrid KEM file encryption tool
    ├── msgpack/        — Tray binary encoding library + tests
    ├── data/           — Sample .tray files for testing
    ├── misc/           — Utilities (hashpass, etc.)
    ├── dist/           — Self-contained distribution (generated)
    └── package.sh      — Distribution builder script
```
