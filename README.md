# pq — Post-Quantum Crypto Tools

C++17 CLI tools and libraries for hybrid PQ+classical key management.
Built against the CRYSTALS reference implementations from
[pq-crystals](https://github.com/pq-crystals).

## Tools

### scotty — Hybrid Tray Keygen

Generates named **hybrid trays** — bundles of paired PQ+classical key slots
covering both KEM and signature roles.

```
scotty keygen [--tray level0|level1|level2-25519|level2|level3|level5]
              --alias <name>
              [--out <file>]
              [--public]
```

| Profile        | KEM-classic | KEM-PQ    | Sig-classic  | Sig-PQ     |
|----------------|-------------|-----------|--------------|------------|
| `level0`       | X25519      | —         | Ed25519      | —          |
| `level1`       | —           | Kyber512  | —            | Dilithium2 |
| `level2-25519` | X25519      | Kyber512  | Ed25519      | Dilithium2 |
| `level2`       | P-256       | Kyber512  | ECDSA P-256  | Dilithium2 |
| `level3`       | P-384       | Kyber768  | ECDSA P-384  | Dilithium3 |
| `level5`       | P-521       | Kyber1024 | ECDSA P-521  | Dilithium5 |

Default profile: `level2-25519`.

**Output modes:**
- Default (no flags): YAML with literal block scalar base64 to stdout
- `--out <file>`: write compact binary MessagePack to `<file>` (~67% of YAML size); auto-prints a human-readable summary to stdout
- `--public`: also emit a companion public tray (alias `<name>.pub`, fresh UUID, no secret keys). With `--out`, written to `<name>.pub.<ext>`; without `--out`, both YAML documents go to stdout

### obi-wan — Hybrid KEM Encryption and Signing

Encrypts and authenticates arbitrary files using a scotty tray. Two operation
modes — **OBIWAN** (encrypt-only) and **HYKE** (encrypt-and-sign).

#### encrypt / decrypt (OBIWAN)

Uses both KEM slots from the tray (classical + PQ), combining their shared
secrets via a KDF, then encrypting with an AEAD cipher.

```
obi-wan encrypt --tray <file> [--kdf SHAKE|KMAC] [--cipher AES-256-GCM|ChaCha20] <target-file>
obi-wan decrypt --tray <file> <target-file>
```

- `--kdf`: `SHAKE` (SHAKE256, default) or `KMAC` (KMAC256)
- `--cipher`: `AES-256-GCM` (default) or `ChaCha20` (ChaCha20-Poly1305)
- KDF/cipher are stored in the wire header and auto-detected on decrypt

Output armor: `-----BEGIN/END OBIWAN ENCRYPTED FILE-----`

Wire format: `"OBIWAN01"` (8B) + KDF byte + cipher byte + `len32+CT_classical` +
`len32+CT_pq` + `nonce(12) || tag(16) || ciphertext`

#### sign / verify (HYKE)

Encrypt-and-sign using **all four slots** from a full tray: both KEM slots for
encryption, both signature slots for authentication. Provides hybrid classical +
post-quantum confidentiality and authenticity in a single operation.

```
obi-wan sign   --tray <file> <target-file>
obi-wan verify --tray <file> <target-file>
```

- `sign` requires a tray with all 4 slots including the signing secret keys
- `verify` requires a tray with all 4 slots including the KEM secret keys
- Both classical (Ed25519 / ECDSA) and PQ (Dilithium) signatures are verified before decryption

Output armor: `-----BEGIN/END HYKE SIGNED FILE-----`

**Tray UUID self-verification**: on load, obi-wan recomputes the tray UUID from the
public key material in each slot (using the same BLAKE3 key-derivation algorithm as
scotty) and rejects the tray if the stored UUID does not match. This detects accidental
corruption or substitution of key material. Trays with a non-v8 UUID are loaded without
verification (backward compat with pre-UUID-derivation trays).

Wire format: `"HYKE"` (4B) + version (2B) + tray\_id (1B) + flags (1B) +
header\_len (4B) + payload\_len (4B) + tray\_uuid (16B) + salt (32B) +
4 × length fields (16B) + `CT_classical` + `CT_pq` + `sig_classical` + `sig_pq` +
`nonce(12) || tag(16) || ciphertext`

**Context binding** prevents key-substitution attacks:
```
ctx = KMAC256(key=pk_classical, msg=pk_pq || "obi-wan-hybrid-sig-v1", outlen=512 bits)
```

**Signed data**: `ctx(64B) || header_fields_and_ciphertexts || encrypted_payload`

**KDF**: `KMAC256(key=ss_classical, msg=ss_pq || CT_classical || CT_pq || salt, outlen=256 bits)`

Security requires breaking **both** the classical and post-quantum KEMs (for
confidentiality) and **both** the classical and PQ signatures (for authenticity).

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

Wire format: top-level msgpack map with short keys (`v`, `a`, `pg`, `t`, `id`, `cr`,
`ex`, `sl`); pk/sk stored as raw bytes (BIN), not base64. Achieves ~67% of YAML
file size across all tray types.

**Dependency**: requires `msgpack-c` header-only library vendored at
`Crystals/msgpack-c/`. Do not remove this directory.

## Build

**Prerequisites**: CMake ≥ 3.15, GCC/Clang with C++17, OpenSSL 3, yaml-cpp.
Kyber and Dilithium ref `.so` files must be built first (one-time):

```bash
cd kyber/ref     && make shared
cd dilithium/ref && make shared
```

**Build individual tools** (from the `Crystals/` root):

```bash
cmake -S pq/scotty    -B pq/scotty/build    && cmake --build pq/scotty/build    -j$(nproc)
cmake -S pq/obi-wan   -B pq/obi-wan/build   && cmake --build pq/obi-wan/build   -j$(nproc)
cmake -S pq/msgpack   -B pq/msgpack/build   && cmake --build pq/msgpack/build   -j$(nproc)
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
    ├── scotty/         — Hybrid PQ+classical tray keygen tool
    ├── obi-wan/        — Hybrid KEM file encryption tool
    ├── msgpack/        — Tray binary encoding library + tests
    ├── misc/           — Utilities (hashpass, etc.)
    └── static-verify/  — Verification project for static kyber+dilithium libs
```
