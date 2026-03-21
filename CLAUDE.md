# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Deps and pq Repository Layout

```
Crystals/
├── kyber/ref/          — Kyber reference C source; statically compiled into obi-wan via CMake
├── kyber/avx2/         — Kyber AVX2 source (not used by the CMake tools)
├── dilithium/ref/      — Dilithium reference C source; statically compiled into obi-wan via CMake
├── dilithium/avx2/     — Dilithium AVX2 source (not used by the CMake tools)
├── msgpack-c/          — msgpack-c header-only library (vendored)
├── XKCP/               — eXtended Keccak Code Package; pre-built libXKCP.so (obi-wan + libcrystals)
├── BLAKE3/             — BLAKE3 source; built + installed to local/ (UUID derivation)
├── oneTBB/             — oneTBB source; built + installed to local/ (BLAKE3 parallelism)
├── local/              — Shared install prefix for BLAKE3 + TBB (CMake finds them here)
└── pq/                 — Main project (git root)
    ├── include/        — Shared headers (tray.hpp domain model)
    ├── scotty/         — Hybrid PQ+classical tray keygen tool (uses libcrystals-1.1)
    ├── obi-wan/        — Hybrid KEM file encryption tool
    ├── libcrystals-1.1/ — Consolidated crypto library; installed to /usr/local via install.sh
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
cmake -S pq/scotty -B pq/scotty/build
cmake --build pq/scotty/build -j$(nproc)
# Binary: pq/scotty/build/scotty
# Requires: libcrystals-1.1 installed to /usr/local (see install.sh below)
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
```

**Install libcrystals-1.1** (required by scotty; installs fat static archive + CMake config to /usr/local):
```bash
sudo bash pq/libcrystals-1.1/install.sh
# Use --skip-build to regenerate the CMake/pkg-config files without rebuilding
```

## API Stability Rules Related to libcrystals-1.x

- Never modify, rename, or remove any function marked `@api-stable`
- Never change the signature of any function declared in the public API, "crystals/crystals.hpp"
- When migrating demo code into libcrystals, add new functions — do not modify existing ones 
- If a migration seems to require changing a stable function, STOP and report the conflict


## Testing

```bash
# obi-wan: encrypt → decrypt (YAML tray, defaults)
./pq/scotty/build/scotty keygen --alias alice --profile level2-25519 > /tmp/alice.tray
echo "hello" > /tmp/plain.txt
./pq/obi-wan/build/obi-wan encrypt --tray /tmp/alice.tray /tmp/plain.txt > /tmp/out.armored
./pq/obi-wan/build/obi-wan decrypt --tray /tmp/alice.tray /tmp/out.armored | diff /tmp/plain.txt -

# obi-wan: KMAC + ChaCha20, YAML tray written to file
./pq/scotty/build/scotty keygen --alias bob --profile level3 --out /tmp/bob.tray
./pq/obi-wan/build/obi-wan encrypt --tray /tmp/bob.tray --kdf KMAC --cipher ChaCha20 /tmp/plain.txt > /tmp/out2.armored
./pq/obi-wan/build/obi-wan decrypt --tray /tmp/bob.tray /tmp/out2.armored | diff /tmp/plain.txt -

# obi-wan: sign → verify (HYKE, all 4 tray types)
./pq/scotty/build/scotty keygen --alias alice --profile level2-25519 > /tmp/alice.tray
./pq/obi-wan/build/obi-wan sign   --tray /tmp/alice.tray /tmp/plain.txt > /tmp/alice.hyke
./pq/obi-wan/build/obi-wan verify --tray /tmp/alice.tray /tmp/alice.hyke | diff /tmp/plain.txt -

# scotty: hybrid tray keygen (crystals group, default)
./scotty keygen --profile level3 --alias alice                          # YAML to stdout (default)
./scotty keygen --alias bob                                             # default profile: level2-25519
./scotty keygen --profile level0 --alias alice                          # classical-only (2 slots)
./scotty keygen --profile level1 --alias alice                          # PQ-only (2 slots)
./scotty keygen --alias alice --out alice.tray                          # YAML to file + auto-summary to stdout
./scotty keygen --alias carol --profile level2-25519 --public           # YAML + companion public YAML (same UUID)
./scotty keygen --alias carol --profile level3 --public --out carol.tray  # carol.tray + carol.pub.tray

# scotty: mceliece+slhdsa group
./scotty keygen --group mceliece+slhdsa --alias alice --profile level1  # 2 slots (PQ-only)
./scotty keygen --group mceliece+slhdsa --alias alice --profile level2  # 4 slots (P-256 + mc460896f + ECDSA + SLH-DSA)
./scotty keygen --group mceliece+slhdsa --alias alice --profile level5  # 4 slots (P-256 + mc8192128f + ECDSA + SLH-DSA)

# scotty: protect / unprotect
./scotty protect   --in alice.tray --out alice.sec.tray --password-file /tmp/pw.txt
./scotty unprotect --in alice.sec.tray --out alice.plain.tray --password-file /tmp/pw.txt

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
scotty generates **hybrid trays** — named bundles of paired PQ+classical key slots, and can
password-protect/unprotect the secret keys in place. scotty is a thin CLI shell backed entirely
by `Crystals::crystals` (libcrystals-1.1).

**Source files** (single file after the libcrystals-1.1 migration):
- `scotty/src/main.cpp` — arg parsing, TTY interaction, password hygiene, file I/O, and
  CLI handlers `cmd_keygen`, `cmd_protect`, `cmd_unprotect`. All crypto delegated to library.

**Library boundary**: The library (`Crystals::crystals`) owns all crypto and serialisation.
scotty owns everything that touches a human (arg parsing, TTY password prompts, entropy
warnings, stdout/stderr) and everything that touches the filesystem.

**Library API used** (all `@api-stable` in `crystals/crystals.hpp`):
- `make_tray`, `make_public_tray`, `validate_tray_uuid`
- `emit_tray_yaml`, `load_tray_yaml`
- `emit_secure_tray_yaml`, `load_secure_tray_yaml`
- `protect_tray`, `unprotect_tray`

**Link deps**: `Crystals::crystals` (fat static archive; pulls in XKCP, BLAKE3, TBB, yaml-cpp,
OpenSSL::Crypto transitively) + `OpenSSL::Crypto` directly (for `openssl/ui.h` EVP_read_pw_string
and `openssl/crypto.h` OPENSSL_cleanse in cmd_protect/cmd_unprotect).

**Output modes**: `keygen` default = YAML stdout; `--out <file>` = YAML to file + auto-summary to stdout;
`--public` = companion public tray (no sk, alias `<name>.pub`, **same UUID** as private tray).
`protect --in <f> --out <f>` = encrypt sk fields → `type: secure-tray` YAML.
`unprotect --in <f> --out <f>` = decrypt sk fields back to plain `type: tray` YAML.

### msgpack Architecture
`pq/msgpack/src/tray_pack.{hpp,cpp}` is used by obi-wan (compiled in) and the standalone library.
The `pq/msgpack/` CMake project builds a standalone `libtraymsgpack.a` and tests for other consumers.

- `pq/include/tray.hpp` — shared domain model included by both scotty and msgpack
- `msgpack/src/tray_pack.hpp` — public API: `tray_mp::pack`, `unpack`, `pack_to_file`, `unpack_from_file`
- `msgpack/src/tray_pack.cpp` — implementation using msgpack-c header-only API
- `msgpack/test/test_roundtrip.cpp` — in-memory mock Tray round-trip test (no external deps)

**Wire format**: top-level msgpack map with short string keys:
```
map(8) { "v"→uint, "a"→str, "pg"→str, "t"→str, "id"→str, "cr"→str, "ex"→str,
         "sl"→array[ map{ "alg"→str, "pk"→bin, "sk"→bin (optional) } ] }
```
pk/sk are stored as raw bytes (msgpack BIN), not base64. Achieves ~67% of YAML file size.

**Dependencies**: msgpack-c header-only at `Crystals/msgpack-c/include` — **required by obi-wan
and the standalone msgpack build**. Do not delete `msgpack-c/`. Compile with `-DMSGPACK_NO_BOOST`
(no Boost needed).

### Static Linking Strategy
**obi-wan**: Kyber and Dilithium are linked statically via CMake `add_subdirectory`. Each build
pulls in 8 static targets: 3 Kyber variants + kyber fips202, 3 Dilithium variants + dilithium
fips202. The two fips202 archives occupy different symbol namespaces
(`pqcrystals_kyber_fips202_ref_*` vs `pqcrystals_dilithium_fips202_ref_*`) and do not collide.
`randombytes()` is compiled directly into obi-wan from `kyber/ref/randombytes.c`.

**scotty**: Uses `libcrystals-1.1.a` — a fat static archive (installed at `/usr/local/lib/`) that
bundles all 8 PQ ref archives + 3 scrypt archives + McEliece + the crystals objects. No separate
`add_subdirectory` or `kyber/ref` source needed. Link via `Crystals::crystals` CMake target.

### RPATH Setup
- **scotty**: RPATH set to `{TBB libdir}:/usr/local/lib` — TBB dir derived from the `TBB::tbb`
  imported target location (baked in by CrystalsConfig.cmake); `/usr/local/lib` covers
  `libXKCP.so` (installed there by `libcrystals-1.1/install.sh`).
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
- scotty: `cmake -S pq/scotty -B pq/scotty/build` (no CMAKE_PREFIX_PATH needed)
  - `find_package(Crystals REQUIRED)` — finds from `/usr/local/lib/cmake/crystals`
  - `find_package(OpenSSL REQUIRED)` — for `openssl/ui.h` + `openssl/crypto.h`
  - TBB and BLAKE3 resolved transitively inside CrystalsConfig.cmake
  - RPATH: `CMAKE_BUILD_RPATH` set to TBB libdir + `/usr/local/lib`
- obi-wan: `cmake -S pq/obi-wan -B pq/obi-wan/build -DCMAKE_PREFIX_PATH=<Crystals>/local`
  - same `add_subdirectory` static targets as scotty; same scrypt setup
  - includes `../msgpack/src`, `../../msgpack-c/include`, `../../XKCP/bin/x86-64/libXKCP.so.headers`
  - links `../../XKCP/bin/x86-64/libXKCP.so` by full path (only remaining dynamic crypto dep)
- msgpack: `cmake -S pq/msgpack -B pq/msgpack/build` (no PREFIX_PATH needed; no BLAKE3/TBB)
- static-verify: `cmake -S pq/static-verify -B pq/static-verify/build` (no external deps)
- obi-wan and msgpack use `../../msgpack-c/include`; all use `../include` (for `tray.hpp`)

## Exit Codes (all tools)
- `0` — success
- `1` — usage/argument error
- `2` — crypto failure (decaps mismatch, invalid signature)
- `3` — I/O error (file not found, wrong PEM header level)
