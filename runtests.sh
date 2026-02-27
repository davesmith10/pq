#!/usr/bin/env bash
# pq/runtests.sh — End-to-end test suite for luke and geordi
# Run from repo root: bash pq/runtests.sh
set -uo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LUKE="$SCRIPT_DIR/dist/bin/luke"
GEORDI="$SCRIPT_DIR/dist/bin/geordi"

# ── Constants ─────────────────────────────────────────────────────────────────
PWHASH="mvaQq+Y0ob/2qBUhtI31b8dIIPnMqry7c9cjuzT+KHQ="

# ── Temp dir (auto-cleaned on exit) ──────────────────────────────────────────
TESTDIR="$(mktemp -d /tmp/pq-test-XXXXXX)"
trap 'rm -rf "$TESTDIR"' EXIT

# ── Counters ──────────────────────────────────────────────────────────────────
PASS=0
FAIL=0

# ── Helpers ───────────────────────────────────────────────────────────────────
section() {
    echo ""
    echo "── $1 ──"
}

expect_ok() {
    local desc="$1"
    shift
    local actual
    "$@" >/dev/null 2>&1; actual=$?
    if [[ $actual -eq 0 ]]; then
        echo "  PASS  $desc"
        PASS=$((PASS+1))
    else
        echo "  FAIL  $desc  (expected exit 0, got $actual)"
        FAIL=$((FAIL+1))
    fi
}

expect_fail() {
    local desc="$1"
    local expected="$2"
    shift 2
    local actual
    "$@" >/dev/null 2>&1; actual=$?
    if [[ $actual -eq $expected ]]; then
        echo "  PASS  $desc"
        PASS=$((PASS+1))
    else
        echo "  FAIL  $desc  (expected exit $expected, got $actual)"
        FAIL=$((FAIL+1))
    fi
}

check_match() {
    local desc="$1"
    local f1="$2"
    local f2="$3"
    if diff -q "$f1" "$f2" >/dev/null 2>&1; then
        echo "  PASS  $desc"
        PASS=$((PASS+1))
    else
        echo "  FAIL  $desc  (files differ)"
        FAIL=$((FAIL+1))
    fi
}

check_contains() {
    local desc="$1"
    local pat="$2"
    local f="$3"
    if grep -qFe "$pat" "$f" 2>/dev/null; then
        echo "  PASS  $desc"
        PASS=$((PASS+1))
    else
        echo "  FAIL  $desc  (pattern not found: $pat)"
        FAIL=$((FAIL+1))
    fi
}

# ── Preflight ─────────────────────────────────────────────────────────────────
for bin in "$LUKE" "$GEORDI"; do
    if [[ ! -x "$bin" ]]; then
        echo "ERROR: binary not found or not executable: $bin"
        echo "Run 'bash pq/package.sh' first."
        exit 1
    fi
done

# ── Plain-text fixture ────────────────────────────────────────────────────────
PLAIN="$TESTDIR/plain.txt"
printf 'The quick brown fox jumps over the lazy dog.\n' > "$PLAIN"

# ─────────────────────────────────────────────────────────────────────────────
section "Group 1 — luke KEM primitives (Kyber768/ref defaults)"
# ─────────────────────────────────────────────────────────────────────────────
G1_PK="$TESTDIR/g1.pk"
G1_SK="$TESTDIR/g1.sk"
G1_KEM="$TESTDIR/g1.kem"
G1_SS1="$TESTDIR/g1-ss1.pem"
G1_SS2="$TESTDIR/g1-ss2.pem"

expect_ok   "keygen --pk --sk" \
    "$LUKE" keygen --pk "$G1_PK" --sk "$G1_SK"

expect_ok   "encaps --pk --kem --ss" \
    "$LUKE" encaps --pk "$G1_PK" --kem "$G1_KEM" --ss "$G1_SS1"

expect_ok   "decaps --sk --kem --ss" \
    "$LUKE" decaps --sk "$G1_SK" --kem "$G1_KEM" --ss "$G1_SS2"

check_match "shared secrets match (encaps == decaps)" "$G1_SS1" "$G1_SS2"

# ─────────────────────────────────────────────────────────────────────────────
section "Group 2 — luke keygen variants"
# ─────────────────────────────────────────────────────────────────────────────
expect_ok   "keygen --level 512 --impl ref" \
    "$LUKE" keygen --level 512 --impl ref \
        --pk "$TESTDIR/g2-k512.pk" --sk "$TESTDIR/g2-k512.sk"

expect_ok   "keygen --level 1024 --impl avx2" \
    "$LUKE" keygen --level 1024 --impl avx2 \
        --pk "$TESTDIR/g2-k1024.pk" --sk "$TESTDIR/g2-k1024.sk"

expect_ok   "keygen --seed (deterministic, run 1)" \
    "$LUKE" keygen --seed "$PWHASH" \
        --pk "$TESTDIR/g2-det1.pk" --sk "$TESTDIR/g2-det1.sk"

expect_ok   "keygen --seed (deterministic, run 2)" \
    "$LUKE" keygen --seed "$PWHASH" \
        --pk "$TESTDIR/g2-det2.pk" --sk "$TESTDIR/g2-det2.sk"

check_match "deterministic keygen: both pk files identical" \
    "$TESTDIR/g2-det1.pk" "$TESTDIR/g2-det2.pk"

# ─────────────────────────────────────────────────────────────────────────────
section "Group 3 — luke encrypt/decrypt (pwHash, file → file)"
# ─────────────────────────────────────────────────────────────────────────────
G3_LUKB="$TESTDIR/g3.lukb"
G3_REC="$TESTDIR/g3-recovered.txt"

expect_ok   "encrypt --pwHash --in --out" \
    "$LUKE" encrypt --pwHash "$PWHASH" --in "$PLAIN" --out "$G3_LUKB"

expect_ok   "decrypt --pwHash --in --out" \
    "$LUKE" decrypt --pwHash "$PWHASH" --in "$G3_LUKB" --out "$G3_REC"

check_match "decrypted file matches original" "$PLAIN" "$G3_REC"

# ─────────────────────────────────────────────────────────────────────────────
section "Group 4 — luke encrypt/decrypt (pwHash, stdout)"
# ─────────────────────────────────────────────────────────────────────────────
G4_LUKB="$TESTDIR/g4.lukb"
G4_RAW="$TESTDIR/g4-stdout-raw.txt"
G4_STRIPPED="$TESTDIR/g4-stripped.txt"

"$LUKE" encrypt --pwHash "$PWHASH" --in "$PLAIN" > "$G4_LUKB" 2>/dev/null
G4_ENC_EXIT=$?
if [[ $G4_ENC_EXIT -eq 0 && -s "$G4_LUKB" ]]; then
    echo "  PASS  encrypt to stdout (exit 0, non-empty output)"
    PASS=$((PASS+1))
else
    echo "  FAIL  encrypt to stdout (exit $G4_ENC_EXIT, empty: $( [[ -s "$G4_LUKB" ]] && echo no || echo yes ))"
    FAIL=$((FAIL+1))
fi

"$LUKE" decrypt --pwHash "$PWHASH" --in "$G4_LUKB" > "$G4_RAW" 2>/dev/null
G4_DEC_EXIT=$?
if [[ $G4_DEC_EXIT -eq 0 ]]; then
    echo "  PASS  decrypt to stdout (exit 0)"
    PASS=$((PASS+1))
else
    echo "  FAIL  decrypt to stdout (exit $G4_DEC_EXIT)"
    FAIL=$((FAIL+1))
fi

# Strip the trailing \n appended by stdout mode, then compare
head -c -1 "$G4_RAW" > "$G4_STRIPPED"
check_match "stdout-decrypted matches original (trailing newline stripped)" \
    "$PLAIN" "$G4_STRIPPED"

# ─────────────────────────────────────────────────────────────────────────────
section "Group 5 — luke encrypt/decrypt (keypair, file → file)"
# ─────────────────────────────────────────────────────────────────────────────
G5_PK="$TESTDIR/g5-alice.pk"
G5_SK="$TESTDIR/g5-alice.sk"
G5_LUKB="$TESTDIR/g5.lukb"
G5_REC="$TESTDIR/g5-recovered.txt"

expect_ok   "keygen (alice)" \
    "$LUKE" keygen --pk "$G5_PK" --sk "$G5_SK"

expect_ok   "encrypt --pk --in --out" \
    "$LUKE" encrypt --pk "$G5_PK" --in "$PLAIN" --out "$G5_LUKB"

expect_ok   "decrypt --sk --in --out" \
    "$LUKE" decrypt --sk "$G5_SK" --in "$G5_LUKB" --out "$G5_REC"

check_match "decrypted file matches original (keypair mode)" "$PLAIN" "$G5_REC"

# ─────────────────────────────────────────────────────────────────────────────
section "Group 6 — geordi keygen / sign / verify (Dilithium3/ref defaults)"
# ─────────────────────────────────────────────────────────────────────────────
G6_PK="$TESTDIR/g6.pub"
G6_SK="$TESTDIR/g6.priv"
G6_SIG="$TESTDIR/g6.sig"
G6_VERIFY_OUT="$TESTDIR/g6-verify.txt"
G6_SIG_STDOUT="$TESTDIR/g6-sig-stdout.pem"

expect_ok   "geordi keygen --pk --sk" \
    "$GEORDI" keygen --pk "$G6_PK" --sk "$G6_SK"

expect_ok   "geordi sign --sk --msg --sig" \
    "$GEORDI" sign --sk "$G6_SK" --msg "$PLAIN" --sig "$G6_SIG"

"$GEORDI" verify --pk "$G6_PK" --msg "$PLAIN" --sig "$G6_SIG" > "$G6_VERIFY_OUT" 2>&1
G6_VERIFY_EXIT=$?
if [[ $G6_VERIFY_EXIT -eq 0 ]]; then
    echo "  PASS  geordi verify (exit 0)"
    PASS=$((PASS+1))
else
    echo "  FAIL  geordi verify (exit $G6_VERIFY_EXIT)"
    FAIL=$((FAIL+1))
fi
check_contains "verify output contains 'Signature valid.'" \
    "Signature valid." "$G6_VERIFY_OUT"

"$GEORDI" sign --sk "$G6_SK" --msg "$PLAIN" > "$G6_SIG_STDOUT" 2>/dev/null
G6_SIGN_STDOUT_EXIT=$?
if [[ $G6_SIGN_STDOUT_EXIT -eq 0 ]]; then
    echo "  PASS  geordi sign to stdout (exit 0)"
    PASS=$((PASS+1))
else
    echo "  FAIL  geordi sign to stdout (exit $G6_SIGN_STDOUT_EXIT)"
    FAIL=$((FAIL+1))
fi
check_contains "sign stdout contains PEM header" \
    "-----BEGIN DILITHIUM3 SIGNATURE-----" "$G6_SIG_STDOUT"

# ─────────────────────────────────────────────────────────────────────────────
section "Group 7 — geordi variants"
# ─────────────────────────────────────────────────────────────────────────────

# Full round-trip at Dilithium2/ref
expect_ok   "geordi keygen --d2 --impl ref" \
    "$GEORDI" keygen --d2 --impl ref \
        --pk "$TESTDIR/g7-d2.pub" --sk "$TESTDIR/g7-d2.priv"

G7_D2_SIG="$TESTDIR/g7-d2.sig"
expect_ok   "geordi sign --d2 --impl ref" \
    "$GEORDI" sign --d2 --impl ref \
        --sk "$TESTDIR/g7-d2.priv" --msg "$PLAIN" --sig "$G7_D2_SIG"

expect_ok   "geordi verify --d2 --impl ref" \
    "$GEORDI" verify --d2 --impl ref \
        --pk "$TESTDIR/g7-d2.pub" --msg "$PLAIN" --sig "$G7_D2_SIG"

# Full round-trip at Dilithium5/avx2
expect_ok   "geordi keygen --d5 --impl avx2" \
    "$GEORDI" keygen --d5 --impl avx2 \
        --pk "$TESTDIR/g7-d5.pub" --sk "$TESTDIR/g7-d5.priv"

G7_SIG="$TESTDIR/g7-d5-avx2.sig"
G7_VERIFY="$TESTDIR/g7-verify.txt"

expect_ok   "geordi sign --d5 --impl avx2" \
    "$GEORDI" sign --d5 --impl avx2 \
        --sk "$TESTDIR/g7-d5.priv" --msg "$PLAIN" --sig "$G7_SIG"

"$GEORDI" verify --d5 --impl avx2 \
    --pk "$TESTDIR/g7-d5.pub" --msg "$PLAIN" --sig "$G7_SIG" > "$G7_VERIFY" 2>&1
G7_VERIFY_EXIT=$?
if [[ $G7_VERIFY_EXIT -eq 0 ]]; then
    echo "  PASS  geordi verify --d5 --impl avx2 (exit 0)"
    PASS=$((PASS+1))
else
    echo "  FAIL  geordi verify --d5 --impl avx2 (exit $G7_VERIFY_EXIT)"
    FAIL=$((FAIL+1))
fi

# Cross-impl interop: sign with ref, verify with avx2 (same algorithm — must interoperate)
G7_CROSS_SIG="$TESTDIR/g7-cross.sig"
expect_ok   "cross-impl: sign --d3 --impl ref" \
    "$GEORDI" sign --d3 --impl ref \
        --sk "$G6_SK" --msg "$PLAIN" --sig "$G7_CROSS_SIG"

expect_ok   "cross-impl: verify --d3 --impl avx2" \
    "$GEORDI" verify --d3 --impl avx2 \
        --pk "$G6_PK" --msg "$PLAIN" --sig "$G7_CROSS_SIG"

# ─────────────────────────────────────────────────────────────────────────────
section "Group 8 — Negative tests"
# ─────────────────────────────────────────────────────────────────────────────

# Wrong pwHash against a pwHash-encrypted bundle
WRONG_HASH="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
expect_fail "luke decrypt wrong pwHash → exit 2" 2 \
    "$LUKE" decrypt --pwHash "$WRONG_HASH" --in "$G3_LUKB" --out /dev/null

# Wrong SK against a keypair-encrypted bundle
G8_WRONG_PK="$TESTDIR/g8-wrong.pk"
G8_WRONG_SK="$TESTDIR/g8-wrong.sk"
"$LUKE" keygen --pk "$G8_WRONG_PK" --sk "$G8_WRONG_SK" >/dev/null 2>&1
expect_fail "luke decrypt wrong SK → exit 2" 2 \
    "$LUKE" decrypt --sk "$G8_WRONG_SK" --in "$G5_LUKB" --out /dev/null

# Tampered message
G8_TAMPERED="$TESTDIR/g8-tampered.txt"
printf 'This message has been tampered with.\n' > "$G8_TAMPERED"
expect_fail "geordi verify tampered message → exit 2" 2 \
    "$GEORDI" verify --pk "$G6_PK" --msg "$G8_TAMPERED" --sig "$G6_SIG"

# Mismatched signature (signed a different message)
G8_MSG2="$TESTDIR/g8-msg2.txt"
G8_SIG2="$TESTDIR/g8-sig2.sig"
printf 'A completely different message.\n' > "$G8_MSG2"
"$GEORDI" sign --sk "$G6_SK" --msg "$G8_MSG2" --sig "$G8_SIG2" >/dev/null 2>&1
expect_fail "geordi verify mismatched sig → exit 2" 2 \
    "$GEORDI" verify --pk "$G6_PK" --msg "$PLAIN" --sig "$G8_SIG2"

# Wrong public key (valid sig, wrong pk)
G8_ALT_PK="$TESTDIR/g8-alt.pub"
G8_ALT_SK="$TESTDIR/g8-alt.priv"
"$GEORDI" keygen --pk "$G8_ALT_PK" --sk "$G8_ALT_SK" >/dev/null 2>&1
expect_fail "geordi verify wrong pk → exit 2" 2 \
    "$GEORDI" verify --pk "$G8_ALT_PK" --msg "$PLAIN" --sig "$G6_SIG"

# Wrong level: sig is DILITHIUM3, but --d2 expects DILITHIUM2 header → I/O error
expect_fail "geordi verify wrong level (--d2 against d3 files) → exit 3" 3 \
    "$GEORDI" verify --d2 --pk "$G6_PK" --msg "$PLAIN" --sig "$G6_SIG"

# Context string mismatch: sign with custom ctx, verify with default
G8_CTX_SIG="$TESTDIR/g8-ctx.sig"
"$GEORDI" sign --sk "$G6_SK" --msg "$PLAIN" --ctx "myapp:v1" --sig "$G8_CTX_SIG" >/dev/null 2>&1
expect_fail "geordi verify ctx mismatch (signed 'myapp:v1', verify default) → exit 2" 2 \
    "$GEORDI" verify --pk "$G6_PK" --msg "$PLAIN" --sig "$G8_CTX_SIG"

# Context string mismatch: sign with default ctx, verify with wrong ctx
expect_fail "geordi verify ctx mismatch (signed default, verify 'myapp:v1') → exit 2" 2 \
    "$GEORDI" verify --pk "$G6_PK" --msg "$PLAIN" --sig "$G6_SIG" --ctx "myapp:v1"

# ─────────────────────────────────────────────────────────────────────────────
section "Group 9 — Usage errors (exit 1)"
# ─────────────────────────────────────────────────────────────────────────────

expect_fail "geordi sign missing --sk → exit 1" 1 \
    "$GEORDI" sign --msg "$PLAIN" --sig /dev/null

expect_fail "geordi verify missing --pk → exit 1" 1 \
    "$GEORDI" verify --msg "$PLAIN" --sig "$G6_SIG"

expect_fail "luke keygen missing --pk → exit 1" 1 \
    "$LUKE" keygen --sk /dev/null

expect_fail "luke encaps missing --kem → exit 1" 1 \
    "$LUKE" encaps --pk "$G1_PK" --ss /dev/null

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "── Results ──"
echo "  $PASS passed, $FAIL failed"
echo ""
[[ $FAIL -eq 0 ]]
