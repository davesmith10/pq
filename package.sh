#!/usr/bin/env bash
# package.sh — build luke, geordi, and scotty and assemble a self-contained dist/
# Usage: bash package.sh [--clean]
#
# Produces:
#   dist/bin/luke   (RPATH: $ORIGIN/../lib/kyber)
#   dist/bin/geordi (RPATH: $ORIGIN/../lib/dilithium)
#   dist/bin/scotty (RPATH: $ORIGIN/../lib/scotty)
#   dist/lib/kyber/*.so
#   dist/lib/dilithium/*.so
#   dist/lib/scotty/*.so   (kyber ref + dilithium ref; fips202 compiled into binary)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$SCRIPT_DIR/dist"
JOBS=$(nproc 2>/dev/null || echo 2)

CLEAN=0
for arg in "$@"; do
    [[ "$arg" == "--clean" ]] && CLEAN=1
done

# ── luke ──────────────────────────────────────────────────────────────────────
echo "=== Building luke ==="
LUKE_BUILD="$SCRIPT_DIR/luke/build"
if [[ $CLEAN -eq 1 && -d "$LUKE_BUILD" ]]; then
    rm -rf "$LUKE_BUILD"
fi
mkdir -p "$LUKE_BUILD"
cmake -S "$SCRIPT_DIR/luke" -B "$LUKE_BUILD" -DCMAKE_INSTALL_PREFIX="$DIST_DIR"
cmake --build "$LUKE_BUILD" -j"$JOBS"
cmake --install "$LUKE_BUILD"

# ── geordi ────────────────────────────────────────────────────────────────────
echo "=== Building geordi ==="
GEORDI_BUILD="$SCRIPT_DIR/geordi/build"
if [[ $CLEAN -eq 1 && -d "$GEORDI_BUILD" ]]; then
    rm -rf "$GEORDI_BUILD"
fi
mkdir -p "$GEORDI_BUILD"
cmake -S "$SCRIPT_DIR/geordi/src" -B "$GEORDI_BUILD" -DCMAKE_INSTALL_PREFIX="$DIST_DIR"
cmake --build "$GEORDI_BUILD" -j"$JOBS"
cmake --install "$GEORDI_BUILD"

# ── scotty ────────────────────────────────────────────────────────────────────
echo "=== Building scotty ==="
SCOTTY_BUILD="$SCRIPT_DIR/scotty/build"
if [[ $CLEAN -eq 1 && -d "$SCOTTY_BUILD" ]]; then
    rm -rf "$SCOTTY_BUILD"
fi
mkdir -p "$SCOTTY_BUILD"
cmake -S "$SCRIPT_DIR/scotty" -B "$SCOTTY_BUILD" -DCMAKE_INSTALL_PREFIX="$DIST_DIR"
cmake --build "$SCOTTY_BUILD" -j"$JOBS"
cmake --install "$SCOTTY_BUILD"

# ── obi-wan ───────────────────────────────────────────────────────────────────
echo "=== Building obi-wan ==="
OBIWAN_BUILD="$SCRIPT_DIR/obi-wan/build"
if [[ $CLEAN -eq 1 && -d "$OBIWAN_BUILD" ]]; then
    rm -rf "$OBIWAN_BUILD"
fi
mkdir -p "$OBIWAN_BUILD"
cmake -S "$SCRIPT_DIR/obi-wan" -B "$OBIWAN_BUILD" -DCMAKE_INSTALL_PREFIX="$DIST_DIR"
cmake --build "$OBIWAN_BUILD" -j"$JOBS"
cmake --install "$OBIWAN_BUILD"

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Distribution assembled at: $DIST_DIR ==="
echo ""
echo "  Binaries:"
ls -lh "$DIST_DIR/bin/"
echo ""
echo "  Kyber libs:"
ls -lh "$DIST_DIR/lib/kyber/"
echo ""
echo "  Dilithium libs:"
ls -lh "$DIST_DIR/lib/dilithium/"
echo ""
echo "  Scotty libs:"
ls -lh "$DIST_DIR/lib/scotty/"
echo ""
echo "  Obi-wan libs:"
ls -lh "$DIST_DIR/lib/obi-wan/"
echo ""
echo "  RPATH check:"
patchelf --print-rpath "$DIST_DIR/bin/luke"
patchelf --print-rpath "$DIST_DIR/bin/geordi"
patchelf --print-rpath "$DIST_DIR/bin/scotty"
patchelf --print-rpath "$DIST_DIR/bin/obi-wan"
