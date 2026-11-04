#!/usr/bin/env bash
# Instrumentación sancov de LLVM; no requiere características nightly de Rust.
set -euo pipefail
cd "$(dirname "$0")/.."
objetivo=$(rustc -vV | sed -n 's/^host: //p')
export RUSTFLAGS='-C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=3 -C llvm-args=-sanitizer-coverage-inline-8bit-counters -C llvm-args=-sanitizer-coverage-pc-table'
export CARGO_TARGET_DIR=${SUAYA_FUZZ_TARGET_DIR:-"$PWD/fuzz/target"}
cargo build --manifest-path fuzz/Cargo.toml --locked --release --target "$objetivo"
for target in escaneres importar_cbom protocolos; do
    mkdir -p "fuzz/corpus/$target"
    "$CARGO_TARGET_DIR/$objetivo/release/$target" "fuzz/corpus/$target" -max_total_time="${SUAYA_FUZZ_SECONDS:-30}" -timeout=10 -rss_limit_mb=1024
done
