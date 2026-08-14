#!/usr/bin/env bash
# Regenerate UniFFI Kotlin + Swift bindings into the checked-in paths.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

cargo build -p engytita-ffi

LIB="$CARGO_TARGET_DIR/debug/libengytita_ffi.dylib"
if [[ ! -f "$LIB" ]]; then
  LIB="$CARGO_TARGET_DIR/debug/libengytita_ffi.so"
fi

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

cargo run -p engytita-ffi --features cli --bin uniffi-bindgen -- generate \
  --library "$LIB" \
  --language kotlin \
  --language swift \
  --out-dir "$OUT"

mkdir -p android/library/generated/org/engytita ios/Engytita/Generated
cp "$OUT/org/engytita/engytita_ffi.kt" android/library/generated/org/engytita/
cp "$OUT/EngytitaFfi.swift" "$OUT/EngytitaFfiFFI.h" "$OUT/EngytitaFfiFFI.modulemap" ios/Engytita/Generated/

echo "Wrote:"
echo "  android/library/generated/org/engytita/engytita_ffi.kt"
echo "  ios/Engytita/Generated/EngytitaFfi.swift"
echo "  ios/Engytita/Generated/EngytitaFfiFFI.h"
echo "  ios/Engytita/Generated/EngytitaFfiFFI.modulemap"
