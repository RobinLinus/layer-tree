#!/usr/bin/env bash
# Generate 3 operator keys and produce config files with pubkeys.
# Run from the prototype/ directory.

set -euo pipefail

DEPLOY_DIR="deploy"
KEYS_DIR="$DEPLOY_DIR/keys"
CONFIG_DIR="$DEPLOY_DIR/config"

mkdir -p "$KEYS_DIR" "$CONFIG_DIR"

# Build the operator binary if needed
cargo build --release --bin operator 2>/dev/null || cargo build --bin operator

OPERATOR_BIN=$(find target -name operator -type f | head -1)
if [ -z "$OPERATOR_BIN" ]; then
    echo "Error: operator binary not found"
    exit 1
fi

# Generate 3 keys
PUBKEYS=()
for i in 0 1 2; do
    KEY_FILE="$KEYS_DIR/operator-$i.bin"
    if [ ! -f "$KEY_FILE" ]; then
        # Generate 32 random bytes
        dd if=/dev/urandom of="$KEY_FILE" bs=32 count=1 2>/dev/null
    fi

    # Extract pubkey by starting operator briefly — or just compute it
    # For now, we generate and note the keys. The operator will print its pubkey on startup.
    echo "Key $i: $KEY_FILE"
done

echo ""
echo "Keys generated in $KEYS_DIR/"
echo ""
echo "To get pubkeys, start each operator and note the logged pubkey."
echo "Then update the config files in $CONFIG_DIR/ with all pubkeys."
echo ""
echo "For quick single-operator dev, use: cargo run --bin operator -- operator.toml"

# Generate config templates
for i in 0 1 2; do
    cat > "$CONFIG_DIR/operator-$i.toml" <<EOF
[operator]
key_file = "/keys/operator-$i.bin"

[network]
chain = "regtest"

[listen]
user_addr = "0.0.0.0:8080"
peer_addr = "0.0.0.0:50051"

[peers]
# Fill in after getting pubkeys from each operator's startup log.
# Order determines signer indices (index 0 = leader).
urls = ["http://operator-0:50051", "http://operator-1:50051", "http://operator-2:50051"]
pubkeys = []

[bitcoind]
rpc_url = "http://bitcoind:18443"
rpc_user = "rpcuser"
rpc_pass = "rpcpassword"

[database]
path = "/data/layer_tree.db"
EOF
done

echo "Config templates written to $CONFIG_DIR/"
echo "Edit pubkeys[] in each config after extracting them from operator logs."
