# padme — Tray Visualizer

`padme` reads a Crystals tray file (produced by `scotty`) and renders its key material as a PNG image. Each slot's bytes — public key and secret key concatenated — become colored pixels in a rainbow-spectrum palette, stacked as sub-rectangles inside a white-bordered image.

The result is a shareable, conversation-starting visual artifact of a cryptographic identity. Every tray looks different; two trays with the same profile will have entirely different color patterns because the key bytes are random.

---

## Usage

```
padme render --tray <file> [--out <file.png>]
```

| Flag | Description |
|------|-------------|
| `--tray <file>` | Tray file to render (YAML or msgpack, auto-detected) |
| `--out <file.png>` | Output path (default: `<alias>.png`) |

```bash
# Generate a tray with scotty, then render it
scotty keygen --alias alice --tray level3 > alice.tray.yaml
padme render --tray alice.tray.yaml --out alice.png

# Or use a binary msgpack tray
scotty keygen --alias bob --tray level5 --out bob.tray
padme render --tray bob.tray --out bob.png
```

Example output line:
```
Rendered tray 'alice' → alice.png (48×309 px, 4 slots)
```

---

## Visual Layout

- **Width**: 48 px (8px left margin + 32px data + 8px right margin)
- **Height**: computed from slot sizes (8px top/bottom margins, 8px gap between slots)
- **Pixels**: 1 pixel per key byte, left-to-right then top-to-bottom per slot
- **Colors**: rainbow spectrum — byte value 0 maps to red, 128 to cyan, 255 back to red
- **Padding**: last partial row of each slot is zero-padded (black → red in the palette)

Example dimensions by tray profile (private trays):

| Profile | Slots | Approx height |
|---------|-------|---------------|
| level0  | 2     | ~28 px        |
| level1  | 2     | ~138 px       |
| level2-25519 | 4 | ~241 px    |
| level2  | 4     | ~241 px       |
| level3  | 4     | ~309 px       |
| level5  | 4     | ~436 px       |

Public trays (no secret keys) are shorter — only pk bytes are colored; sk bytes are absent.

---

## The Idea

Post-quantum key material is large and opaque — a Dilithium5 secret key is 4896 bytes of
random-looking binary. Viewing it as a color image makes the scale and structure tangible:
you can see how much larger a level5 tray is than a level0, and you can visually confirm
that two trays are different without reading hex.

It's also a conversation piece. "Here's what my cryptographic identity looks like" is a
more compelling introduction to post-quantum crypto than a YAML dump.

---

## Build

Requires: `cmake`, `g++`, `yaml-cpp`, and BLAKE3 + TBB installed to `Crystals/local/`.

```bash
cmake -S pq/padme -B pq/padme/build \
  -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local
cmake --build pq/padme/build -j$(nproc)
# Binary: pq/padme/build/padme
```

`padme` compiles lodepng directly from source (vendored in this directory) and pulls in the
tray-loading code from `pq/libcrystals/src/` — no separate library install step needed.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Usage / argument error |
| 2 | Tray load failure (corrupt file, UUID mismatch) |
| 3 | I/O error (PNG write failed) |

---

## Dependencies

| Dependency | Role |
|------------|------|
| [lodepng](https://lodev.org/lodepng/) | PNG encoding (vendored, single `.h`/`.cpp`) |
| yaml-cpp 0.6 | YAML tray parsing |
| BLAKE3 | UUID self-verification when loading trays |
| TBB | Runtime dep of BLAKE3 (parallel hashing) |
| msgpack-c (header-only) | msgpack tray parsing |
