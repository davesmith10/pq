# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Deps and pq Repository Layout

```
Crystals/
├── kyber/ref/          — Kyber reference C source; statically compiled into tools via CMake
├── kyber/avx2/         — Kyber AVX2 source (not used by the CMake tools)
├── dilithium/ref/      — Dilithium reference C source; statically compiled via CMake
├── dilithium/avx2/     — Dilithium AVX2 source (not used by the CMake tools)
├── msgpack-c/          — msgpack-c header-only library (vendored)
├── XKCP/               — eXtended Keccak Code Package; pre-built libXKCP.so (obi-wan only)
├── BLAKE3/             — BLAKE3 source; built + installed to local/ (UUID derivation)
├── oneTBB/             — oneTBB source; built + installed to local/ (BLAKE3 parallelism)
├── local/              — Shared install prefix for BLAKE3 + TBB (CMake finds them here)
└── pq/                 — Main project (git root)
    ├── include/        — Shared headers (tray.hpp domain model)
    ├── scotty/         — Hybrid PQ+classical tray keygen tool
    ├── obi-wan/        — Hybrid KEM file encryption tool
    ├── msgpack/        — Tray binary encoding library + tests
    ├── misc/           — Utilities (hashpass, etc.)
    └── static-verify/  — Standalone project verifying the static Kyber + Dilithium CMake
                          libraries; links all 8 static targets + randombytes.c, runs KEM
                          and signature round-trips for all 6 parameter sets
```

## Build Commands

**Kyber and Dilithium** are compiled statically from source via CMake `add_subdirectory` —
no separate `make shared` step is needed for the tools.

**Build scotty** (hybrid PQ+classical tray keygen):
```bash
cmake -S pq/scotty -B pq/scotty/build \
  -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local
cmake --build pq/scotty/build -j$(nproc)
# Binary: pq/scotty/build/scotty
```

**Build obi-wan** (hybrid KEM file encryption):
```bash
cmake -S pq/obi-wan -B pq/obi-wan/build \
  -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local
cmake --build pq/obi-wan/build -j$(nproc)
# Binary: pq/obi-wan/build/obi-wan
```

**Build msgpack** (tray binary encoding library + tests):
```bash
cmake -S pq/msgpack -B pq/msgpack/build
cmake --build pq/msgpack/build -j$(nproc)
# Library: pq/msgpack/build/libtraymsgpack.a
# Tests:   pq/msgpack/build/test_roundtrip
#          pq/msgpack/build/test_from_yaml
```

## Testing

```bash
# obi-wan: encrypt → decrypt (YAML tray, defaults)
./pq/scotty/build/scotty keygen --alias alice --tray level2-25519 > /tmp/alice.tray
echo "hello" > /tmp/plain.txt
./pq/obi-wan/build/obi-wan encrypt --tray /tmp/alice.tray /tmp/plain.txt > /tmp/out.armored
./pq/obi-wan/build/obi-wan decrypt --tray /tmp/alice.tray /tmp/out.armored | diff /tmp/plain.txt -

# obi-wan: KMAC + ChaCha20, msgpack tray
./pq/scotty/build/scotty keygen --alias bob --tray level3 --out /tmp/bob.tray
./pq/obi-wan/build/obi-wan encrypt --tray /tmp/bob.tray --kdf KMAC --cipher ChaCha20 /tmp/plain.txt > /tmp/out2.armored
./pq/obi-wan/build/obi-wan decrypt --tray /tmp/bob.tray /tmp/out2.armored | diff /tmp/plain.txt -

# obi-wan: sign → verify (HYKE, all 4 tray types)
./pq/scotty/build/scotty keygen --alias alice --tray level2-25519 > /tmp/alice.tray
./pq/obi-wan/build/obi-wan sign   --tray /tmp/alice.tray /tmp/plain.txt > /tmp/alice.hyke
./pq/obi-wan/build/obi-wan verify --tray /tmp/alice.tray /tmp/alice.hyke | diff /tmp/plain.txt -

# scotty: hybrid tray keygen
./scotty keygen --tray level3 --alias alice                          # YAML to stdout (default)
./scotty keygen --alias bob                                          # default profile: level2-25519
./scotty keygen --tray level0 --alias alice                          # classical-only (2 slots)
./scotty keygen --tray level1 --alias alice                          # PQ-only (2 slots)
./scotty keygen --alias alice --out alice.tray                       # binary msgpack to file + auto-summary
./scotty keygen --tray level3 --alias bob --out bob.tray
./scotty keygen --alias carol --tray level2-25519 --public           # YAML + companion public YAML
./scotty keygen --alias carol --tray level3 --public --out carol.tray  # carol.tray + carol.pub.tray

# msgpack: round-trip tests
./pq/msgpack/build/test_roundtrip

# Kyber upstream tests (1000 cycles each level)
cd kyber/ref && make && ./test/test_kyber768

# Dilithium upstream tests (10000 cycles each level)
cd dilithium/ref && make && ./test/test_dilithium3
```

## Architecture

### obi-wan Architecture
obi-wan has two operation modes: **OBIWAN** (encrypt/decrypt using both KEM slots) and
**HYKE** (sign/verify using all four slots — both KEMs for encryption, both sig slots for auth).

**Source files:**
- `obi-wan/src/main.cpp` — arg parsing, encrypt/decrypt/sign/verify dispatch
- `obi-wan/src/kyber_api.hpp` — `extern "C"` for Kyber{512,768,1024} ref `enc`/`dec`
- `obi-wan/src/kyber_kem.{hpp,cpp}` — `encaps()`/`decaps()` wrappers
- `obi-wan/src/ec_kem.{hpp,cpp}` — ECDH encaps/decaps (X25519 raw key API; P-curves via `OSSL_PARAM_BLD`)
- `obi-wan/src/ec_sig.{hpp,cpp}` — classical signing: Ed25519 (raw key + NULL md); ECDSA P-256/384/521 (DER→P1363)
- `obi-wan/src/dilithium_api.hpp` — `extern "C"` for Dilithium{2,3,5} ref `_signature`/`_verify`
- `obi-wan/src/dilithium_sig.{hpp,cpp}` — PQ signing wrappers (ref only, no ctx string)
- `obi-wan/src/kdf.hpp` — header-only: SHAKE256, KMAC256 (OBIWAN), `derive_key_hyke()`, `compute_hyke_ctx()`
- `obi-wan/src/symmetric.hpp` — header-only AES-256-GCM and ChaCha20-Poly1305
- `obi-wan/src/hyke_format.hpp` — header-only: `HykeHeader`, pack/unpack, armor/dearmor, UUID parser
- `obi-wan/src/tray_reader.{hpp,cpp}` — load YAML or msgpack tray (auto-detect by first byte)
- `obi-wan/src/armor.{hpp,cpp}` — OBIWAN wire format pack/unpack + base64 armor/dearmor
- `obi-wan/src/base64.{hpp,cpp}` — base64 encode/decode

**XKCP dependency**: `XKCP/bin/x86-64/libXKCP.so` (linked by full path; pre-built, do not
delete) + headers at `XKCP/bin/x86-64/libXKCP.so.headers/` (`SimpleFIPS202.h` for SHAKE256,
`SP800-185.h` for KMAC256). This is the only remaining dynamic dependency for obi-wan.

**fips202 linking**: both `pqcrystals_kyber_fips202_ref` and `pqcrystals_dilithium_fips202_ref`
are compiled as separate static archives via `add_subdirectory`, each with their own symbol
namespace. No OBJECT libraries or `-rdynamic` required.

**OBIWAN KDF input construction**:
- SHAKE256: `SHAKE256(len32(SS_cl)||SS_cl||len32(SS_pq)||SS_pq||len32(CT_cl)||CT_cl||len32(CT_pq)||CT_pq, 32B)`
- KMAC256: `KMAC256(key=SS_cl, msg=len32(SS_pq)||...|CT_pq, custom="hybrid-kem-file-encryption-v1", 256b)`

**HYKE KDF and context binding**:
- KDF: `KMAC256(key=ss_cl, msg=ss_pq||CT_cl||CT_pq||salt, custom="obi-wan-hybrid-sig-v1", 256b)` (no len32 prefixes)
- ctx: `KMAC256(key=pk_cl, msg=pk_pq||"obi-wan-hybrid-sig-v1", outlen=512b)` → 64-byte context
- Signed region: `ctx || partial_header(80+N+M bytes) || encrypted_payload`

**ECDSA signature format**: P1363 (raw r||s, fixed size) rather than DER, so signature lengths
are known from the tray type before signing. Conversion: `EVP_DigestSign` → DER → `d2i_ECDSA_SIG`
→ `BN_bn2binpad` for sign; reverse via `BN_bin2bn` → `ECDSA_SIG_set0` → `i2d_ECDSA_SIG` for verify.
Fixed sizes: P-256=64B, P-384=96B, P-521=132B.

**Slot selection**: uses `alg_name` matching — KEM classical: `{X25519,P-256,P-384,P-521}`;
KEM PQ: prefix `"Kyber"`; Sig classical: `{Ed25519,ECDSA P-256,ECDSA P-384,ECDSA P-521}`;
Sig PQ: `{Dilithium2,Dilithium3,Dilithium5}`.

### scotty Architecture
scotty generates **hybrid trays** — named bundles of paired PQ+classical key slots.
- `pq/include/tray.hpp` — shared `Tray`/`Slot` structs and `TrayType` enum (domain model, not scotty-internal)
- `scotty/src/tray.cpp` — `make_tray()` implementation, UUID + ISO 8601 timestamps
- `ec_ops.{hpp,cpp}` — OpenSSL EVP keygen for X25519, Ed25519, P-256, P-384, P-521
- `kyber_ops.{hpp,cpp}` + `kyber_api.hpp` — ref-only Kyber keygen wrapper
- `dilithium_ops.{hpp,cpp}` + `dilithium_api.hpp` — ref-only Dilithium keygen wrapper
- `yaml_io.{hpp,cpp}` — yaml-cpp YAML emission with literal block scalars
- `base64.{hpp,cpp}` — Base64 encode/decode
- `pq/msgpack/src/tray_pack.{hpp,cpp}` — compiled directly into scotty for `--out` binary output

**Output modes**: default = YAML stdout; `--out <file>` = binary msgpack + auto-summary to stdout; `--public` = also emit companion public tray (no sk fields, fresh UUID, alias `<name>.pub`).

**scotty fips202 linking strategy**: Both kyber and dilithium need their own `fips202` symbol
namespace (`pqcrystals_kyber_fips202_ref_*` vs `pqcrystals_dilithium_fips202_ref_*`). This is
handled cleanly by the static CMake builds: `kyber/ref/CMakeLists.txt` compiles
`pqcrystals_kyber_fips202_ref` and `dilithium/ref/CMakeLists.txt` compiles
`pqcrystals_dilithium_fips202_ref` — each with its own `-I` path, producing distinct symbol
names. No OBJECT libraries or `-rdynamic` required.

### msgpack Architecture
`pq/msgpack/src/tray_pack.{hpp,cpp}` is shared between scotty and the standalone library.
scotty compiles `tray_pack.cpp` directly (see scotty CMakeLists.txt). The `pq/msgpack/`
CMake project builds a standalone `libtraymsgpack.a` and tests for other consumers.

- `pq/include/tray.hpp` — shared domain model included by both scotty and msgpack
- `msgpack/src/tray_pack.hpp` — public API: `tray_mp::pack`, `unpack`, `pack_to_file`, `unpack_from_file`
- `msgpack/src/tray_pack.cpp` — implementation using msgpack-c header-only API
- `msgpack/test/test_roundtrip.cpp` — in-memory mock Tray round-trip test (no external deps)
- `msgpack/test/test_from_yaml.cpp` — parses real `.tray` YAML → pack → unpack → verify

**Wire format**: top-level msgpack map with short string keys:
```
map(8) { "v"→uint, "a"→str, "pg"→str, "t"→str, "id"→str, "cr"→str, "ex"→str,
         "sl"→array[ map{ "alg"→str, "pk"→bin, "sk"→bin (optional) } ] }
```
pk/sk are stored as raw bytes (msgpack BIN), not base64. Achieves ~67% of YAML file size.

**Dependencies**: msgpack-c header-only at `Crystals/msgpack-c/include` — **required by both
scotty and msgpack builds**. Do not delete `msgpack-c/`. Compile with `-DMSGPACK_NO_BOOST`
(no Boost needed). `test_from_yaml` also links yaml-cpp and scotty's `base64.cpp`.

### Static Linking Strategy
Kyber and Dilithium are linked **statically** into both scotty and obi-wan via CMake
`add_subdirectory`. Each build pulls in 8 static targets: 3 Kyber variants + kyber fips202,
3 Dilithium variants + dilithium fips202. The two fips202 archives occupy different symbol
namespaces (`pqcrystals_kyber_fips202_ref_*` vs `pqcrystals_dilithium_fips202_ref_*`) and
do not collide. There are no shared `.so` files from kyber/ref or dilithium/ref at runtime.

`randombytes()` is not included in any archive — it is compiled directly into each binary
from `kyber/ref/randombytes.c`.

### RPATH Setup
- **scotty**: RPATH set to the TBB library directory (derived from the `TBB::tbb` imported
  target location); no kyber/dilithium `.so` paths needed (all statically linked).
- **obi-wan**: RPATH set to `XKCP/bin/x86-64/` (for libXKCP.so) and the TBB library dir.
  Install RPATH uses `$ORIGIN/../lib/obi-wan` (relative, for portable installs).

### Key Size Constants (from `*_api.hpp`)
| Level | Public Key | Secret Key | Ciphertext/Sig |
|-------|-----------|-----------|----------------|
| Kyber512 | 800 B | 1632 B | 768 B |
| Kyber768 | 1184 B | 2400 B | 1088 B |
| Kyber1024 | 1568 B | 3168 B | 1568 B |
| Dilithium2 | 1312 B | **2560 B** | 2420 B |
| Dilithium3 | 1952 B | **4032 B** | 3309 B |
| Dilithium5 | 2592 B | **4896 B** | 4627 B |

(Note: Dilithium sk sizes differ from NIST ML-DSA spec; use values from `dilithium/ref/api.h`)

## CMakeLists.txt Paths
- scotty: `cmake -S pq/scotty -B pq/scotty/build -DCMAKE_PREFIX_PATH=<Crystals>/local`
  - `add_subdirectory(../../kyber/ref)` + `add_subdirectory(../../dilithium/ref)` for 8 static targets
  - includes `../msgpack/src` and `../../msgpack-c/include` for the tray_pack module
  - `find_package(BLAKE3)` / `find_package(TBB)` resolved via `CMAKE_PREFIX_PATH`
- obi-wan: `cmake -S pq/obi-wan -B pq/obi-wan/build -DCMAKE_PREFIX_PATH=<Crystals>/local`
  - same `add_subdirectory` static targets as scotty
  - includes `../msgpack/src`, `../../msgpack-c/include`, `../../XKCP/bin/x86-64/libXKCP.so.headers`
  - links `../../XKCP/bin/x86-64/libXKCP.so` by full path (only remaining dynamic crypto dep)
- msgpack: `cmake -S pq/msgpack -B pq/msgpack/build` (no PREFIX_PATH needed; no BLAKE3/TBB)
- static-verify: `cmake -S pq/static-verify -B pq/static-verify/build` (no external deps)
- msgpack and scotty both use `../../msgpack-c/include` and `../include` (for `tray.hpp`)

## Exit Codes (all tools)
- `0` — success
- `1` — usage/argument error
- `2` — crypto failure (decaps mismatch, invalid signature)
- `3` — I/O error (file not found, wrong PEM header level)
