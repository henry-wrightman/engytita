# engytita-ffi

UniFFI bindings for Engytita.

- Opaque handles only - long-term secrets never cross the FFI boundary
- Session STS (16) and transport (32) keys are the only key bytes returned
- Kotlin bindings: `android/library/generated/`
- Swift bindings: `ios/Engytita/Generated/`

```bash
# Build the cdylib, then generate bindings:
cargo build -p engytita-ffi
cargo run -p engytita-ffi --features cli --bin uniffi-bindgen -- generate \
  --library target/debug/libengytita_ffi.dylib \
  --language kotlin --language swift \
  --out-dir /tmp/engytita-bindings
```

See `scripts/generate-bindings.sh` for the checked-in output paths.
