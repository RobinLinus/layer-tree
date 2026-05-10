# Layer Tree

A Bitcoin L2 prototype. Users deposit BTC into a shared UTXO managed by N operators. Balances are tracked off-chain via an operator blockchain. Transfers are instant. Withdrawals are cooperative by default, but every user can always exit unilaterally: operators continuously sign an exit tree that pre-commits each user's balance to an on-chain output they can claim at any time without operator cooperation.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Operator 0  │◄───►│ Operator 1  │◄───►│ Operator 2  │   Peer protocol
│  (leader)   │     │             │     │             │   (block proposals,
└──────┬──────┘     └─────────────┘     └─────────────┘    MuSig2 signing)
       │
       │  REST API (:8080)
       ▼
  ┌─────────┐
  │ Browser │  BIP-340 Schnorr auth
  │ Wallet  │  for transfers & withdrawals
  └─────────┘
```

**Crates:**
- `core` — exit tree construction, transaction building, state management, signing
- `operator` — REST API, peer protocol, block production, state driver, chain monitor
- `proto` — message types for peer communication

## Quick Start (Single Operator)

```bash
# Build
cargo build --release

# Run (uses operator.toml defaults: regtest, localhost:8080)
cargo run --release --bin operator

# Open wallet
open http://localhost:8080
```

The operator generates a key on first run (`operator_key.bin`), initializes SQLite (`layer_tree.db`), and starts:
- **User API** on `:8080` — REST endpoints + browser wallet
- **Peer API** on `:50051` — operator-to-operator protocol

## Configuration

See [`operator.toml`](operator.toml) for all options:

```toml
[operator]
key_file = "./operator_key.bin"

[network]
chain = "regtest"           # or "signet"

[listen]
user_addr = "127.0.0.1:8080"
peer_addr = "127.0.0.1:50051"

[peers]
urls = []                   # peer operator URLs
pubkeys = []                # all operator pubkeys (ordered, determines leader)

[database]
path = "./layer_tree.db"

# Optional: connect to bitcoind for chain monitoring
# [bitcoind]
# rpc_url = "http://127.0.0.1:18443"
# rpc_user = "rpcuser"
# rpc_pass = "rpcpassword"

# Optional: protect admin endpoints
# [admin]
# token = "secret"
```

## Multi-Operator Setup (Docker)

Run a 3-operator cluster with bitcoind on regtest:

```bash
# 1. Generate operator keys and config templates
./scripts/gen_keys.sh

# 2. Start each operator once to get its pubkey from the log output
#    Then edit deploy/config/operator-{0,1,2}.toml and fill in pubkeys[]

# 3. Start everything
docker compose up -d

# 4. Bootstrap the epoch (set the pool UTXO via admin endpoint)
curl -X POST http://localhost:8080/api/admin/set_epoch \
  -H 'Content-Type: application/json' \
  -d '{"epoch_id": 0, "outpoint": "<txid>:<vout>", "amount_sats": 1000000}'

# 5. Open wallet
open http://localhost:8080
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check (chain height, epoch status, mempool size) |
| GET | `/api/info` | Operator info (chain, fanout, epoch, pool UTXO) |
| GET | `/api/balance/{pubkey}` | User balance lookup |
| POST | `/api/deposit` | Register a pending deposit |
| POST | `/api/transfer` | Send sats to another user (requires BIP-340 signature) |
| POST | `/api/withdrawal` | Request on-chain withdrawal (requires BIP-340 signature) |
| POST | `/api/admin/set_epoch` | Bootstrap epoch with pool UTXO (admin) |

## Browser Wallet

The built-in wallet at `http://localhost:8080` supports:
- Key generation (BIP-340 x-only keypair stored in localStorage)
- Balance checking
- Deposits (register outpoint + amount)
- Transfers (Schnorr-signed, instant)
- Withdrawals (Schnorr-signed, queued for L1 settlement)

## Tests

```bash
# Run all tests
cargo test

# Run just operator tests (integration + e2e + multi-operator)
cargo test --package layer-tree-operator
```

## License

MIT
