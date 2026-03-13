# padme — Tray Visualizer, Decoder, and Encapsulator

`padme` reads a Crystals tray file (produced by `scotty`) and renders its key material as a
PNG image. Each key byte becomes one colored pixel in a rainbow-spectrum palette. The image
is a shareable, conversation-starting visual artifact of a cryptographic identity — and it
is also a fully recoverable archive: `padme decode` reads the PNG back and reconstructs a
working tray.

`padme encaps` goes further: it renders the tray into a 256-pixel-wide annotated image and
encrypts the private key bytes with a password (scrypt + AES-256-GCM). The resulting PNG
carries the public keys in plaintext pixels, the encrypted secret keys as ciphertext pixels,
and all decryption metadata in an iTXt chunk. `padme decaps` reverses the process.

---

## Commands

```
padme render  --tray <file>     [--out <file.png>]
padme decode  --tray <file.png> [--out <file>]
padme encaps  --tray <file>     [--out <file.png>] [--pwfile <file>]
padme decaps  --tray <file.png> [--out <file>]     [--pwfile <file>]
```

---

### render

Visualizes a tray as a compact PNG (88 px wide for 4-slot trays).

| Flag | Description |
|------|-------------|
| `--tray <file>` | Source tray (YAML or msgpack, auto-detected) |
| `--out <file.png>` | Output PNG (default: `<alias>.png`) |

```bash
scotty keygen --alias alice --tray level3 > alice.tray.yaml
padme render --tray alice.tray.yaml --out alice.png
# Rendered tray 'alice' → alice.png (88×232 px, 4 slots)

padme render --tray bob.tray --out bob.png   # msgpack input works too
```

---

### decode

Recovers a tray from a `padme render` PNG. Refuses to operate on encaps PNGs (use `decaps`).

| Flag | Description |
|------|-------------|
| `--tray <file.png>` | padme render PNG to decode |
| `--out <file>` | Output file: YAML if `.yaml`/`.yml`, msgpack otherwise (default: YAML to stdout) |

```bash
# Inspect on stdout
padme decode --tray alice.png

# Recover as YAML
padme decode --tray alice.png --out alice-recovered.yaml

# Recover as msgpack
padme decode --tray alice.png --out alice-recovered.tray

# Verify recovered tray is cryptographically identical
obi-wan encrypt --tray alice.tray      plaintext.txt > enc.arm
obi-wan decrypt --tray alice-recovered.tray enc.arm    # succeeds
```

---

### encaps

Renders a tray into a 256-pixel-wide annotated PNG and password-encrypts the private key
bytes in place. Public keys are stored as plaintext rainbow pixels; secret keys are replaced
with AES-256-GCM ciphertext pixels. The PNG carries a human-readable header (alias, profile,
UUID) and a copyright footer.

| Flag | Description |
|------|-------------|
| `--tray <file>` | Source tray (YAML or msgpack) |
| `--out <file.png>` | Output PNG (default: `<alias>_enc.png`) |
| `--pwfile <file>` | Read password from file (newline stripped). Prompts `password:` + `again:` if omitted. |

```bash
# Interactive (prompts twice)
padme encaps --tray alice.tray --out alice_enc.png

# From a password file
echo "hunter2" > pw.txt
padme encaps --tray alice.tray --pwfile pw.txt --out alice_enc.png
# Encaps: tray 'alice' → alice_enc.png (scrypt N=2^19, AES-256-GCM)
```

---

### decaps

Decrypts the private keys from an encaps PNG and reconstructs the original tray.

| Flag | Description |
|------|-------------|
| `--tray <file.png>` | encaps PNG produced by `padme encaps` |
| `--out <file>` | Output file: YAML if `.yaml`/`.yml`, msgpack otherwise (default: YAML to stdout) |
| `--pwfile <file>` | Read password from file. Prompts `password:` once if omitted. |

```bash
# Recover to stdout (YAML)
padme decaps --tray alice_enc.png

# Recover to YAML file
padme decaps --tray alice_enc.png --out alice-recovered.yaml

# Recover to msgpack file
padme decaps --tray alice_enc.png --out alice-recovered.tray

# Wrong password → exit 2
echo "wrong" | padme decaps --tray alice_enc.png --pwfile /dev/stdin
# Error: decryption failed — wrong password or corrupted image
```

---

## Encryption Scheme (encaps/decaps)

```
Key hierarchy:
  password + random-salt (16 B) ──scrypt──► wrap_key (32 B)
  wrap_key ──AES-256-GCM──► data_key (32 B random)    [KEM block: 60 px]
  data_key ──AES-256-GCM──► all_sk (all slot secret keys concatenated)

KDF: scrypt(N=2^19, r=8, p=1) via OpenSSL EVP_PBE_scrypt
Symmetric: AES-256-GCM (nonce randomly generated per operation)
```

The KEM block (kem_nonce ∥ kem_tag ∥ encrypted_data_key = 60 bytes) is embedded as a
centered row of colored pixels between the key blocks and the footer. Decryption metadata
(salt, scrypt params, SK nonce, SK tag) is stored in a `crystals-encaps` iTXt chunk.

---

## Visual Layout

### render / decode (88 px wide)

For 4-slot trays (level2-25519, level2, level3, level5):

```
┌────────────────────────────────────────┐
│  classical pk  │  classical sk         │  ← small (32–194 bytes each)
├────────────────┼───────────────────────┤
│  PQ pk         │  PQ sk                │  ← large (2112–8736 bytes each)
└────────────────┴───────────────────────┘
```

- **Width**: 88 px (8px margin + 32px + 8px gap + 32px + 8px margin)
- **Pixels**: 1 pixel per key byte, rainbow spectrum (byte 0 → red, 128 → cyan, 255 → near-red)
- **Padding**: last partial row zero-padded

For 2-slot trays (level0, level1), slots are stacked vertically in a single 48 px wide column.

#### Dimensions by profile (private trays)

| Profile | Layout | Width | Height |
|---------|--------|-------|--------|
| level0 | stack | 48 px | ~28 px |
| level1 | stack | 48 px | ~221 px |
| level2-25519 | grid | 88 px | ~157 px |
| level2 | grid | 88 px | ~157 px |
| level3 | grid | 88 px | ~232 px |
| level5 | grid | 88 px | ~285 px |

### encaps / decaps (256 px wide)

```
┌─────────────────────────────────────────────────────────┐  ← 12px margin
│  PADME Tray - <profile>                                 │  ← header line 1
│  <uuid>                                                 │  ← header line 2
│                                                         │  ← 8px gap
│  [classical pk · 112px]  │  [classical sk (enc) · 112px]│  ← top section
│                                                         │  ← 8px gap
│  [PQ pk · 112px]         │  [PQ sk (enc) · 112px]      │  ← bottom section
│                                                         │  ← 8px gap
│              [KEM block — 60 pixels, centered]          │  ← 1-pixel row
│                                                         │  ← 8px gap
│              © 2026 David R. Smith                      │  ← footer line 1
│              All Rights Reserved                        │  ← footer line 2
└─────────────────────────────────────────────────────────┘  ← 12px margin
```

Public key pixels are unchanged rainbow colors. Secret key pixels are the AES-256-GCM
ciphertext of the original key bytes — visually indistinguishable but cryptographically
locked to the password.

---

## PNG Format Notes

### crystals-tray iTXt chunk (render and encaps)

```
alias=alice
id=986f58d0-20f9-8713-ac05-604b637967e1
profile=level3
created=2026-03-12T02:35:52Z
expires=2028-03-12T02:35:52Z
```

### crystals-encaps iTXt chunk (encaps only)

```
salt=<base64-16-bytes>
n_log2=19
r=8
p=1
sk_nonce=<base64-12-bytes>
sk_tag=<base64-16-bytes>
```

The presence of the `crystals-encaps` chunk distinguishes encaps PNGs from render PNGs.
`padme decode` refuses encaps PNGs; `padme decaps` requires them.

### Palette inversion

`byte_to_rgb` maps 256 byte values to 256 distinct RGB triples — a bijection, so the
inverse is exact. The hue range is 0°–358.6° (dividing by 256, not 255) to prevent byte 0
and byte 255 from colliding at pure red (hue 360° = hue 0°).

---

## Build

Requires: `cmake`, `g++`, `yaml-cpp`, `OpenSSL 3`, and BLAKE3 + TBB installed to `Crystals/local/`.

```bash
cmake -S pq/padme -B pq/padme/build \
  -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local
cmake --build pq/padme/build -j$(nproc)
# Binary: pq/padme/build/padme
```

`padme` compiles lodepng directly from source (vendored in this directory) and pulls in
tray I/O code from `pq/libcrystals/src/` — no separate library install step needed.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Usage / argument error |
| 2 | Crypto / decode error (wrong password, bad palette pixel, unknown profile) |
| 3 | I/O error (file not found, PNG read/write failure) |

---

## Dependencies

| Dependency | Role |
|------------|------|
| [lodepng](https://lodev.org/lodepng/) | PNG encode/decode with iTXt chunk support (vendored) |
| OpenSSL 3 | scrypt KDF (`EVP_PBE_scrypt`) + AES-256-GCM (`encaps`/`decaps`) |
| yaml-cpp 0.6 | YAML tray parsing and emission |
| BLAKE3 | UUID self-verification when loading trays |
| TBB | Runtime dep of BLAKE3 (parallel hashing) |
| msgpack-c (header-only) | msgpack tray pack/unpack |
