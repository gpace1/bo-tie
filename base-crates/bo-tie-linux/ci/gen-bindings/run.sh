#!/bin/bash
set -ex

CRATE_ROOT=$(pwd)/'../../'
BINDINGS_DESTINATION="$CRATE_ROOT/src/device"
TARGET_DIR="$CRATE_ROOT/../../target/ci/bo-tie-linux/bindings"

mkdir -p "$TARGET_DIR"

docker build -o "$TARGET_DIR" .

cp "$TARGET_DIR/bindings.rs" "$BINDINGS_DESTINATION"


