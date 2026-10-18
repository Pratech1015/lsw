#!/bin/sh
# Minimal smoke tests for the LSW2 scaffold.
set -u

BIN="${BIN:-build/lsw2}"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '  ok: %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

if [ ! -x "$BIN" ]; then
    echo "binary not found: $BIN (run make first)"
    exit 1
fi

out=$("$BIN" --version 2>&1)
case "$out" in
    *"lsw2 0.0."*) pass "--version prints version" ;;
    *) fail "--version prints version (got: $out)" ;;
esac

case "$out" in
    *"WSL2 approach"*) pass "--version identifies the WSL2 line" ;;
    *) fail "--version identifies the WSL2 line" ;;
esac

if "$BIN" --help >/dev/null 2>&1; then
    pass "--help exits successfully"
else
    fail "--help exits successfully"
fi

if "$BIN" --shutdown >/dev/null 2>&1; then
    fail "--shutdown fails until the VM monitor exists"
else
    pass "--shutdown fails until the VM monitor exists"
fi

# An unimplemented command must fail loudly rather than exit 0.
if "$BIN" definitely-not-a-command >/dev/null 2>&1; then
    fail "unknown commands are rejected"
else
    pass "unknown commands are rejected"
fi

echo ""
echo "============================================="
printf '  PASS: %s  FAIL: %s\n' "$PASS" "$FAIL"
echo "============================================="

[ "$FAIL" -eq 0 ] || exit 1
exit 0
