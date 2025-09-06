#!/usr/bin/env bash
set -eEuo pipefail

readonly POCKETIC_VERSION="9.0.1"
readonly POCKETIC_URL="https://github.com/dfinity/pocketic/releases/download/${POCKETIC_VERSION}/pocket-ic-x86_64-linux.gz"
readonly POCKETIC_CHECKSUM="237272216498074e5250a0685813b96632963ff9abbc51a7030d9b625985028d"
readonly WORKDIR="$(pwd)"
readonly POCKETIC_BIN="${WORKDIR}/pocket-ic"
readonly CARGO_TARGET_DIR="${WORKDIR}/target"
readonly CANISTER_WASM_PATH="${CARGO_TARGET_DIR}/wasm32-unknown-unknown/release/canister.wasm"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >&2; }

log "Downloading PocketIC v${POCKETIC_VERSION}"
curl -fsSL --retry 3 --retry-delay 5 "${POCKETIC_URL}" -o pocket-ic.gz || {
  log "Failed to download PocketIC"
  exit 1
}
echo "${POCKETIC_CHECKSUM} pocket-ic.gz" | sha256sum -c - || {
  log "PocketIC checksum verification failed"
  exit 1
}
log "Extracting PocketIC"
gzip -df pocket-ic.gz || { log "Failed to extract PocketIC"; exit 1; }
chmod +x "${POCKETIC_BIN}" || { log "Failed to make PocketIC executable"; exit 1; }
export POCKET_IC_BIN="${POCKETIC_BIN}"
log "PocketIC setup completed"

log "Building the canister wasm"
cd ./canister/canister_backend
cargo build --target wasm32-unknown-unknown --release
log "Canister wasm built successfully at ${CANISTER_WASM_PATH}"

log "Running unit tests using all features enabled"
cargo test --all-features --profile dev --workspace --lib || { log "Unit tests failed"; exit 1; }
log "Unit tests completed successfully"

log "Running integration tests with all features enabled"
export WASM_PATH="${CANISTER_WASM_PATH}"
cargo test --all-features --profile dev --workspace --test '*' -- --nocapture || { log "Integration tests failed"; exit 1; }
log "Integration tests completed successfully"