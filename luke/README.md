# luke

A command-line tool for a post-quantum kem algorithm  using **CRYSTALS-Kyber** (now standardized as NIST ML-KEM). 
Supports Kyber512, Kyber768, and Kyber1024 with both reference and AVX2-optimized implementations.

## Use Cases

Key exchange is the typical case but a kem is useful for basic encryption, too.

---

## What is Kyber?

Kyber is a **Key Encapsulation Mechanism (KEM)** — not a traditional encrypt/decrypt cipher. It lets two parties establish a shared secret over an insecure channel, 
and that shared secret can then be used to key a symmetric cipher like AES-256.

It is quantum-resistant: breaking it requires solving hard lattice problems that are believed to be infeasible even for quantum computers.

---

## How a KEM Works (the three-step flow)

Understanding the three commands requires understanding the roles of the two parties:

```
Alice (receiver)                         Bob (sender)
────────────────                         ────────────
1. luke keygen → alice.pk, alice.sk
   Share alice.pk publicly
                                         2. luke encaps --pk alice.pk
                                              → bob.kem  (send to Alice)
                                              → bob.ss   (Bob's 265 bit asymmetric encryption key, keep secret)

3. luke decaps --sk alice.sk --kem bob.kem
     → alice.ss  (Alice's shared secret, 265 bit asymmetric encryption key)

Result: bob.ss == alice.ss  (same 32-byte secret, both sides)
```

**Step 1 — keygen (Alice):** Alice generates a public/secret keypair. She keeps the secret key (`alice.sk`) private and shares the public key (`alice.pk`) with anyone who wants to communicate with her.

**Step 2 — encaps (Bob):** Bob runs encapsulation using Alice's public key. Kyber internally generates a random shared secret and encrypts it into a ciphertext. Bob gets two outputs:
- `bob.kem` — the ciphertext, which he sends to Alice
- `bob.ss` — the shared secret (32 bytes), which he keeps and uses to encrypt his actual data

**Step 3 — decaps (Alice):** Alice runs decapsulation using her secret key and the ciphertext she received from Bob. She recovers the same 32-byte shared secret. Both sides now have identical key material without it ever having traveled over the wire.

The shared secret is then typically used as a key for AES-256-GCM or another symmetric cipher — `luke` itself only handles the key exchange.

---

## Build

Prerequisites: `cmake`, `g++` (with C++17), and the Kyber `.so` libraries.

The Kyber source repository must sit **alongside** the `pq/` repo, not inside it:

```
<parent>/
├── kyber/    ← cloned from pq-crystals/kyber
└── pq/
    └── luke/
```

Run all commands from `<parent>/`.

**Step 1 — build the Kyber shared libraries:**

```sh
git clone https://github.com/pq-crystals/kyber.git kyber
cd kyber/ref && make shared && cd ../..
cd kyber/avx2 && make shared && cd ../..
# The Kyber Makefile does not generate this alias automatically:
ln -s libpqcrystals_fips202_ref.so kyber/avx2/libpqcrystals_fips202_avx2.so
```

**Step 2 — build luke:**

*Recommended — build and assemble a self-contained distribution:*

```sh
cd pq && bash package.sh
```

This produces `pq/dist/` with the binary in `bin/` and all required `.so` files bundled in `lib/kyber/`. The `dist/` directory can be copied to any Linux x86-64 machine without further setup.

*Development build (runs in-place, no install step):*

```sh
mkdir -p pq/luke/build && cd pq/luke/build
cmake ..
make
```

The binary is written to `pq/luke/build/luke`.

---

## Usage

```
luke <command> [options]

Commands:
  keygen    Generate a Kyber keypair
  encaps    Encapsulate a shared secret using a public key
  decaps    Decapsulate a ciphertext using a secret key

Options:
  --level <512|768|1024>   Security level (default: 768)
  --impl  <ref|avx2>       Implementation (default: ref)
  --pk    <file>           Public key file
  --sk    <file>           Secret key file
  --kem   <file>           Ciphertext file
  --ss    <file>           Shared secret output file
```

### keygen

Generates a keypair. Requires `--pk` and `--sk`.

```sh
luke keygen --pk alice.pk --sk alice.sk
luke keygen --level 1024 --impl avx2 --pk alice.pk --sk alice.sk
```

### encaps

Reads a public key, produces a ciphertext and a shared secret. Requires `--pk`, `--kem`, and `--ss`.

```sh
luke encaps --pk alice.pk --kem alice.kem --ss my_shared_secret.ss
```

The `--level` and `--impl` flags must match what was used during `keygen` — `luke` validates the PEM headers and will error if they do not match.

### decaps

Reads a secret key and ciphertext, recovers the shared secret. Requires `--sk`, `--kem`, and `--ss`.

```sh
luke decaps --sk alice.sk --kem alice.kem --ss my_shared_secret.ss
```

---

## Complete Example

```sh
# Alice generates her keypair
./luke keygen --pk alice.pk --sk alice.sk

# Bob encapsulates a shared secret using Alice's public key
./luke encaps --pk alice.pk --kem for_alice.kem --ss bob.ss

# Alice decapsulates using her secret key and the ciphertext Bob sent
./luke decaps --sk alice.sk --kem for_alice.kem --ss alice.ss

# Verify both shared secrets are identical
diff <(cat bob.ss) <(cat alice.ss) && echo "Shared secrets match!"
```

---

## File Format

All files use PEM-like Base64 ASCII armor, for example:

```
-----BEGIN KYBER768 PUBLIC KEY-----
... base64 data ...
-----END KYBER768 PUBLIC KEY-----
```

The header tag encodes the security level (`KYBER512`, `KYBER768`, or `KYBER1024`). `encaps` and `decaps` validate that the file's header matches the `--level` flag, so mismatched keys are caught early.

### Key and ciphertext sizes (raw bytes)

| Parameter | Public key | Secret key | Ciphertext | Shared secret |
|-----------|-----------|-----------|-----------|--------------|
| Kyber512  | 800       | 1632      | 768       | 32           |
| Kyber768  | 1184      | 2400      | 1088      | 32           |
| Kyber1024 | 1568      | 3168      | 1568      | 32           |

The shared secret is always 32 bytes regardless of security level.

---

## Security Levels

| Level     | NIST equivalent | Comparable classical security |
|-----------|----------------|-------------------------------|
| Kyber512  | ML-KEM-512     | ~AES-128                      |
| Kyber768  | ML-KEM-768     | ~AES-192 (recommended)        |
| Kyber1024 | ML-KEM-1024    | ~AES-256                      |

Kyber768 is the default and is the recommended level for most use cases.

---

## Implementations

- `ref` — Portable C reference implementation. Works on any platform.
- `avx2` — Optimized for x86-64 processors with AVX2 support. Significantly faster.

The two implementations are interoperable: a keypair generated with `--impl ref` can be used with `--impl avx2` for encaps/decaps and vice versa, since they implement the same algorithm.

---

## Keys are not interchangeable with scotty / Dilithium

Kyber (used by `luke`) and Dilithium (used by [`scotty`](../scotty/)) are both built on
**module lattice** mathematics — specifically, both derive their security from variants of
the Module Learning With Errors (MLWE) problem — but they are distinct algorithms with
incompatible key structures and completely different purposes:

| Property | Kyber (luke) | Dilithium (scotty) |
|----------|--------------|--------------------|
| Purpose | Key encapsulation (KEM) | Digital signatures |
| Hard problem | Module-LWE (decryption hardness) | Module-LWE + Module-SIS (signing + verification) |
| Public key role | Encrypt a shared secret | Verify a signature |
| Secret key role | Decrypt the shared secret | Produce a signature |
| Key sizes (level 3) | pk: 1184 B, sk: 2400 B | pk: 1952 B, sk: 4032 B |

A Kyber secret key **cannot** be used to sign a message, and a Dilithium secret key
**cannot** be used in a KEM. The internal polynomial representations, noise distributions,
and key-derivation procedures differ between the two. Swapping files between the tools
will be caught immediately by the PEM header check (`KYBER768` vs `DILITHIUM3`), but even
if that check were bypassed the raw bytes would be structurally meaningless to the other
algorithm.

If you need both confidentiality and authentication, generate **separate** Kyber and
Dilithium keypairs and use `luke` for key exchange and `scotty` for signing.

---

## Exit Codes

| Code | Meaning       |
|------|---------------|
| 0    | Success       |
| 1    | Usage error   |
| 2    | Crypto error  |
| 3    | I/O error     |

---

## Source Layout

```
luke/
├── CMakeLists.txt
└── src/
    ├── main.cpp        # argument parsing and command dispatch
    ├── kyber_api.hpp   # extern "C" declarations + KyberParams struct
    ├── kyber_ops.cpp   # keygen / encaps / decaps wrappers
    ├── kyber_ops.hpp
    ├── pem_io.cpp      # read_pem / write_pem
    ├── pem_io.hpp
    ├── base64.cpp      # Base64 encode/decode
    └── base64.hpp
```
