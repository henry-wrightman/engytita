#!/usr/bin/env bash
# Build engytita-ffi as an XCFramework for the iOS Demo.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim)
for t in "${TARGETS[@]}"; do
  rustup target add "$t" >/dev/null
done

echo "Building engytita-ffi (release) for iOS device + simulator…"
cargo build -p engytita-ffi --release --target aarch64-apple-ios
cargo build -p engytita-ffi --release --target aarch64-apple-ios-sim

HDR_DIR="$ROOT/ios/Demo/Native/Headers"
OUT_FW="$ROOT/ios/Demo/Native/EngytitaFfi.xcframework"
mkdir -p "$HDR_DIR"
cp "$ROOT/ios/Engytita/Generated/EngytitaFfiFFI.h" "$HDR_DIR/"
# UniFFI module map name must match canImport(EngytitaFfiFFI)
cat >"$HDR_DIR/module.modulemap" <<'EOF'
module EngytitaFfiFFI {
    header "EngytitaFfiFFI.h"
    export *
}
EOF

rm -rf "$OUT_FW"
xcodebuild -create-xcframework \
  -library "$CARGO_TARGET_DIR/aarch64-apple-ios/release/libengytita_ffi.a" \
  -headers "$HDR_DIR" \
  -library "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libengytita_ffi.a" \
  -headers "$HDR_DIR" \
  -output "$OUT_FW"

echo "Wrote $OUT_FW"
echo "Open ios/Demo/EngytitaDemo.xcodeproj after generating the project (see ios/Demo/README.md)."
