# libcrystals v1.0

Hybrid post-quantum crypto library with a frozen public API.

## API contract

**The single public header is `crystals/crystals.hpp`.**
All declarations marked `// @api-stable v1.0` are frozen — signatures will not change.
Consumers must only `#include "crystals/crystals.hpp"` and must not include anything from `src/`.

The API stability test (`test/api_stability_test.cpp`) enforces this at compile time via
`static_assert`. Any breaking change will fail to compile that file.

## Structure

```
pq/libcrystals-1.0/
  include/crystals/
    crystals.hpp         ← THE public API (frozen v1.0)
  src/
    *.hpp + *.cpp        ← private implementation (24 headers, 15 .cpp files)
  test/
    test_crystals.cpp    ← 13-section functional test
    api_stability_test.cpp ← static_assert compile-time API enforcement
  CMakeLists.txt
  install.sh
```

## Build

```bash
cmake -S pq/libcrystals-1.0 -B pq/libcrystals-1.0/build \
  -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local
cmake --build pq/libcrystals-1.0/build -j$(nproc)
```

## Run tests

```bash
# Functional tests (13 sections)
./pq/libcrystals-1.0/build/test_crystals

# API stability test (compiles + exits 0 = all static_asserts pass)
./pq/libcrystals-1.0/build/api_stability_test
```

## Install

```bash
./pq/libcrystals-1.0/install.sh [--prefix <dir>] [--crystals-root <dir>]
```

## Dependencies

- OpenSSL 3.x (EVP API)
- yaml-cpp
- BLAKE3 (from `Crystals/local/`)
- oneTBB (from `Crystals/local/`)
- XKCP (dynamic: `libXKCP.so`, for SHAKE256/KMAC256)
- Kyber ref + Dilithium ref (statically compiled via `add_subdirectory`)
- scrypt (statically compiled from source)
- msgpack-c (header-only, vendored)
