# luke

A command-line tool for post-quantum cryptography using **CRYSTALS-Kyber** (now standardized as NIST ML-KEM).
Supports Kyber512, Kyber768, and Kyber1024 with both reference and AVX2-optimized implementations.

Provides two usage modes:
- **KEM primitives** (`keygen` / `encaps` / `decaps`) — low-level key exchange building blocks
- **Hybrid file encryption** (`encrypt` / `decrypt`) — complete password-based or keypair-based file encryption using Kyber + AES-256-GCM

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
                                              → bob.ss   (Bob's 256-bit shared secret, keep private)

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
  encrypt   Encrypt a file (Kyber KEM + AES-256-GCM)
  decrypt   Decrypt a .lukb bundle file

Options:
  --level <512|768|1024>   Security level (default: 768)
  --impl  <ref|avx2>       Implementation (default: ref)
  --pk    <file>           Public key file
  --sk    <file>           Secret key file
  --kem     <file>           Ciphertext file (encaps/decaps)
  --ss      <file>           Shared secret output file (encaps/decaps)
  --seed    <base64>         32-byte deterministic seed (keygen/encaps)
  --pwHash  <base64>         Alias for --seed; preferred name for encrypt/decrypt
  --in      <file>           Input plaintext or bundle file (encrypt/decrypt)
  --out     <file>           Output bundle or plaintext file (encrypt/decrypt; default: stdout)
```

### keygen

Generates a keypair. Requires `--pk` and `--sk`.

```sh
luke keygen --pk alice.pk --sk alice.sk
luke keygen --level 1024 --impl avx2 --pk alice.pk --sk alice.sk
```

Pass `--seed` to generate a keypair deterministically from a 256-bit seed (see [Deterministic Mode](#deterministic-mode)):

```sh
luke keygen --seed "$(openssl rand -base64 32)" --pk alice.pk --sk alice.sk
```

### encaps

Reads a public key, produces a ciphertext and a shared secret. Requires `--pk`, `--kem`, and `--ss`.

```sh
luke encaps --pk alice.pk --kem alice.kem --ss my_shared_secret.ss
```

The `--level` and `--impl` flags must match what was used during `keygen` — `luke` validates the PEM headers and will error if they do not match.

Pass `--seed` for deterministic encapsulation:

```sh
luke encaps --seed "$(openssl rand -base64 32)" --pk alice.pk --kem alice.kem --ss my_shared_secret.ss
```

### decaps

Reads a secret key and ciphertext, recovers the shared secret. Requires `--sk`, `--kem`, and `--ss`.

```sh
luke decaps --sk alice.sk --kem alice.kem --ss my_shared_secret.ss
```

Decapsulation is always deterministic; `--seed` is not applicable.

### encrypt

Encrypts a file using Kyber (KEM) + AES-256-GCM (symmetric cipher). Requires `--in`, plus either `--pwHash` or `--pk`. `--out` is optional — if omitted, the base64 bundle is written to stdout.

**With `--pwHash` (password-based):** derives the keypair deterministically from the seed, encapsulates a random session key against it, and encrypts the file. The secret key is never written to disk — it is reconstructed from the same seed at decrypt time.

```sh
luke encrypt --pwHash "$SEED" --in plaintext.txt --out ciphertext.lukb
luke encrypt --pwHash "$SEED" --in plaintext.txt          # bundle → stdout
```

**With `--pk` (keypair-based):** uses an existing public key file. The corresponding `--sk` file must be available at decrypt time.

```sh
luke encrypt --pk alice.pk --in plaintext.txt --out ciphertext.lukb
luke encrypt --pk alice.pk --in plaintext.txt              # bundle → stdout
```

The output is a base64-encoded binary bundle (no PEM header/footer) containing the Kyber ciphertext, AES-GCM nonce, authentication tag, and encrypted payload (see [Bundle Format](#bundle-format-lukb)).

### decrypt

Decrypts a `.lukb` bundle. Requires `--in`, plus either `--pwHash` or `--sk`. `--out` is optional — if omitted, the recovered plaintext is written to stdout.

**With `--pwHash`:** reconstructs the keypair from the seed, decapsulates the Kyber ciphertext to recover the session key, then decrypts.

```sh
luke decrypt --pwHash "$SEED" --in ciphertext.lukb --out plaintext.txt
luke decrypt --pwHash "$SEED" --in ciphertext.lukb          # plaintext → stdout
```

**With `--sk`:** uses an existing secret key file.

```sh
luke decrypt --sk alice.sk --in ciphertext.lukb --out plaintext.txt
luke decrypt --sk alice.sk --in ciphertext.lukb              # plaintext → stdout
```

If the wrong seed or key is supplied, the AES-GCM authentication tag will not verify and `luke` exits with code 2 (`Crypto error: AES-GCM decryption failed (authentication)`). No partial plaintext is written.

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

## Password-Based Hybrid Encryption

Beyond key exchange, `luke` supports a self-contained hybrid encryption scheme that protects a file with nothing more than a strong password. The scheme combines Kyber (post-quantum KEM) with AES-256-GCM (authenticated symmetric cipher).

### How it works

```
ENCRYPT
───────
password ──→ hashpass ──→ seed (32-byte SHA-256 hash)
seed ────→ keygen --seed ──→ (pk, sk)     sk is ephemeral; never stored
pk ──────→ encaps ─────→ (kem_ct, ss)    ss = 32-byte random session key
ss ──────→ AES-256-GCM(nonce, plaintext) → ciphertext + tag

bundle written to disk:
  header | kem_ct | nonce | tag | ciphertext

DECRYPT
───────
password ──→ hashpass ──→ same seed
seed ────→ keygen --seed ──→ same (pk, sk)
sk + kem_ct ──→ decaps ──→ same ss
ss ──────→ AES-256-GCM-verify-then-decrypt ──→ plaintext
```

The `--seed` flag on `encrypt` and `decrypt` accepts the base64 output of `hashpass` (or any other 32-byte base64 value). Both sides regenerate the same Kyber keypair from the seed on demand, so the secret key is never stored anywhere — it only exists in memory for the duration of the operation.

### Why Kyber instead of just hashing the password?

Using Kyber as an intermediate step provides **layered security**:

- The Kyber KEM ciphertext inside the bundle binds the session key (`ss`) to the keypair. A post-quantum adversary who intercepts the bundle cannot recover `ss` without either knowing the password or breaking Kyber's lattice hardness assumption.
- The session key `ss` is freshly randomised on every encryption, even when the same password is reused. Two files encrypted with the same password produce different session keys and different ciphertexts.
- AES-GCM's authentication tag provides integrity: any tampering with the bundle — or use of the wrong password — is detected before any plaintext is exposed.

### Example: complete password-based round-trip

```sh
# 1. Derive a 32-byte seed from a strong password using hashpass
SEED=$(./hashpass)          # prompts silently; outputs base64 to stdout

# 2. Encrypt (to file)
luke encrypt --pwHash "$SEED" --in report.pdf --out report.pdf.lukb

# 3. Decrypt (to file, on the same or another machine — no key files needed)
luke decrypt --pwHash "$SEED" --in report.pdf.lukb --out report.pdf

# Or decrypt directly to stdout
luke decrypt --pwHash "$SEED" --in report.pdf.lukb

# Wrong password → authentication failure, no partial output
luke decrypt --pwHash "$WRONG" --in report.pdf.lukb --out out.pdf
# Crypto error: AES-GCM decryption failed (authentication)
```

### Example: keypair-based encryption (traditional KEM flow)

When the keypair is managed separately (e.g. Alice's key is on a server, Bob encrypts to her):

```sh
# Alice generates and keeps her keypair
luke keygen --pk alice.pk --sk alice.sk

# Bob encrypts to Alice's public key — no secret key needed at encrypt time
luke encrypt --pk alice.pk --in message.txt --out message.lukb

# Alice decrypts with her secret key
luke decrypt --sk alice.sk --in message.lukb --out message.txt
```

---

## Bundle Format (`.lukb`)

`encrypt` writes a **base64-encoded** binary bundle (a single line, no PEM header/footer). The underlying binary layout uses little-endian integers:

| Field      | Size (bytes)       | Contents                              |
|------------|--------------------|---------------------------------------|
| magic      | 4                  | `L` `U` `K` `B`                      |
| version    | 1                  | `0x01`                                |
| level      | 2                  | Kyber level: 512, 768, or 1024        |
| kem_ct     | 768 / 1088 / 1568  | Kyber KEM ciphertext                  |
| nonce      | 12                 | AES-GCM nonce (random per encryption) |
| tag        | 16                 | AES-GCM authentication tag            |
| ciphertext | N                  | AES-256-GCM encrypted payload         |

The bundle is self-describing: the `level` field tells `decrypt` which key size to expect, so no `--level` flag is needed at decrypt time. The base64 encoding makes bundles safe to embed in JSON, emails, or shell scripts.

---

## PEM Key Format

All key and shared-secret files use PEM-like Base64 ASCII armor, for example:

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

## Keys are not interchangeable with geordi / Dilithium

Kyber (used by `luke`) and Dilithium (used by [`geordi`](../geordi/)) are both built on
**module lattice** mathematics — specifically, both derive their security from variants of
the Module Learning With Errors (MLWE) problem — but they are distinct algorithms with
incompatible key structures and completely different purposes:

| Property | Kyber (luke) | Dilithium (geordi) |
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
Dilithium keypairs and use `luke` for key exchange and `geordi` for signing.

---

## Deterministic Mode

By default, `keygen` and `encaps` call the operating system's random-number generator. Passing `--seed` (or its alias `--pwHash`) routes them through the library's `_derand` variants instead, making the output fully reproducible from the seed alone.

**Seed format:** a standard base64-encoded string that decodes to exactly 32 bytes (256 bits). Generate one with:

```sh
openssl rand -base64 32
```

**How the seed is used internally:**

| Command | Seed handling |
|---------|---------------|
| `keygen` | The 32-byte seed is expanded to 64 bytes via SHAKE256, then passed to `keypair_derand`. The first 32 bytes seed the key matrix; the second 32 bytes are stored in the secret key for CCA rejection sampling. |
| `encaps` | The 32-byte seed is passed directly to `enc_derand`, which uses it to sample all error polynomials. |
| `decaps` | Always deterministic; no seed needed or accepted. |

The SHAKE256 expansion means the same 32-byte seed always produces the same 64-byte input to keygen — the seed is a compact, stable identity for the keypair.

**Example: deterministic round-trip**

```sh
KEYSEED="$(openssl rand -base64 32)"
ENCSEED="$(openssl rand -base64 32)"

# Regenerate the same keypair at any time from KEYSEED
luke keygen --seed "$KEYSEED" --pk alice.pk --sk alice.sk

# Deterministic encaps: same ENCSEED + same pk → same ciphertext and shared secret
luke encaps --seed "$ENCSEED" --pk alice.pk --kem alice.kem --ss bob.ss

# Decaps is unchanged
luke decaps --sk alice.sk --kem alice.kem --ss alice.ss
```

**Error handling:** if `--seed`/`--pwHash` cannot be decoded as base64, or the decoded length is not exactly 32 bytes, `luke` exits with code 1 (usage error) before any cryptographic operation is attempted.

**Security note:** a seed is long-term key material. Treat it with the same care as a secret key — anyone who knows the seed can regenerate the keypair or replay the encapsulation.

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
    ├── kyber_ops.cpp   # keygen / encaps / decaps / *_derand wrappers
    ├── kyber_ops.hpp
    ├── aes_gcm.hpp     # header-only AES-256-GCM encrypt/decrypt (OpenSSL EVP)
    ├── bundle.hpp      # header-only .lukb bundle read/write
    ├── pem_io.cpp      # read_pem / write_pem
    ├── pem_io.hpp
    ├── base64.cpp      # Base64 encode/decode
    └── base64.hpp
```
