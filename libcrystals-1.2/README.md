# libcrystals v1.1

Hybrid post-quantum crypto library with a frozen public API.

## API contract

**The single public header is `crystals/crystals.hpp`.**

- Declarations marked `// @api-stable v1.0` are **frozen** — signatures will never change.
- Declarations marked `// @api-candidate-1.1` are stable within this release but may be promoted to `@api-stable` in a future version.
- Consumers must only `#include "crystals/crystals.hpp"` and must not include anything from `src/`.

Two compile-time stability tests enforce the contract:
- `api_stability_test-1.0.cpp` — frozen v1.0 API (must never fail)
- `api_stability_test-1.1.cpp` — v1.1 additions (TrayType McEliece variants, `mcs::`, `mceliece_kem::`, `slhdsa_sig::`)

## What's in v1.1

v1.1 adds the **McEliece + SLH-DSA** namespace group on top of the frozen v1.0 API:

| Namespace | Functions | Notes |
|-----------|-----------|-------|
| `mcs` | `keygen_mceliece()`, `keygen_slhdsa()` | Key generation |
| `mceliece_kem` | `encaps()`, `decaps()` | Classic McEliece KEM (5 param sets) |
| `slhdsa_sig` | `is_slhdsa_sig()`, `sig_bytes()`, `sign()`, `verify()` | SLH-DSA signatures (5 variants) |

**McEliece param sets:** `mceliece348864f`, `mceliece460896f`, `mceliece6688128f`, `mceliece6960119f`, `mceliece8192128f`

**SLH-DSA variants:** `SLH-DSA-SHA2-128f`, `SLH-DSA-SHA2-192f`, `SLH-DSA-SHA2-256f`, `SLH-DSA-SHAKE-192f`, `SLH-DSA-SHAKE-256f`

`TrayType` gains five new enumerators: `McEliece_Level1` through `McEliece_Level5`.

HYKE wire format TrayID extended: `0x05`=McEliece_Level2 … `0x08`=McEliece_Level5
(McEliece_Level1 has no classical slots and cannot be used with HYKE).

## Structure

```
pq/libcrystals-1.1/
  include/crystals/
    crystals.hpp             ← THE public API (v1.0 frozen + v1.1 candidates)
  src/
    *.hpp + *.cpp            ← private implementation
    mceliece_ops.{hpp,cpp}   ← McEliece keygen (mcs namespace)
    slhdsa_ops.{hpp,cpp}     ← SLH-DSA keygen (mcs namespace)
    mceliece_kem.{hpp,cpp}   ← McEliece KEM encaps/decaps
    slhdsa_sig.{hpp,cpp}     ← SLH-DSA sign/verify
    mceliece_randombytes.c   ← randombytes shim for libmceliece
    hyke_format.hpp          ← HYKE wire format (TrayID 0x01–0x08)
  test/
    test_crystals.cpp        ← 15-section functional test (451 assertions)
    api_stability_test-1.0.cpp ← static_assert enforcement of frozen v1.0 API
    api_stability_test-1.1.cpp ← static_assert enforcement of v1.1 additions
  CMakeLists.txt
  install.sh
```

## Build

```bash
cmake -S pq/libcrystals-1.1 -B pq/libcrystals-1.1/build \
  -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local
cmake --build pq/libcrystals-1.1/build -j$(nproc)
```

The build type is `RelWithDebInfo` (`-O2 -g`): optimised with full debug symbols.
Swap to `-DCMAKE_BUILD_TYPE=Debug` for `-O0 -g` if you need unoptimised debugging.

## Run tests

```bash
# Functional tests (15 sections, 451 assertions)
./pq/libcrystals-1.1/build/test_crystals

# API stability (compile + exit 0 = all static_asserts pass)
./pq/libcrystals-1.1/build/api_stability_test_10 && echo "v1.0 OK"
./pq/libcrystals-1.1/build/api_stability_test_11 && echo "v1.1 OK"
```

## Install

```bash
./pq/libcrystals-1.1/install.sh [--prefix <dir>] [--crystals-root <dir>]
```

Produces a fat `libcrystals-1.1.a` that bundles Kyber ref, Dilithium ref, scrypt, and
libmceliece — consumers link one archive plus the dynamic deps below.

## Dependencies

**Static (bundled into fat archive by install.sh):**
- Kyber ref + Dilithium ref (compiled via `add_subdirectory`)
- scrypt (compiled from source)
- libmceliece (`/usr/local/lib/libmceliece.a`)

**Dynamic (must be present at runtime):**
- OpenSSL 3.x (EVP API — McEliece keygen, SLH-DSA, EC keys)
- XKCP (`libXKCP.so` — SHAKE256/KMAC256)
- BLAKE3 (from `Crystals/local/` — UUID derivation)
- oneTBB (from `Crystals/local/` — BLAKE3 parallelism)
- yaml-cpp
