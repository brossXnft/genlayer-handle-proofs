#!/usr/bin/env bash
# Build the contract exactly as deployed: wasm32-wasip1 release, wasm-opt -Oz,
# genvm.version section. Prints the SHA-256 to compare with the deployed code.
set -euo pipefail
cd "$(dirname "$0")/.."
WASM_OPT=${WASM_OPT:-wasm-opt}
cargo build --release --target wasm32-wasip1 -p handle-proofs
mkdir -p dist
"$WASM_OPT" -Oz --enable-bulk-memory --enable-sign-ext --enable-mutable-globals \
  --enable-nontrapping-float-to-int target/wasm32-wasip1/release/handle-proofs.wasm -o dist/handle-proofs.opt.wasm
python3 tools/wasm_strip.py dist/handle-proofs.opt.wasm dist/handle-proofs.wasm --version v0.3.0 >/dev/null
rm dist/handle-proofs.opt.wasm
sha256sum dist/handle-proofs.wasm
