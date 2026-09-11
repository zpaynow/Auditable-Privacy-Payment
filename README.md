# Auditable Privacy Payment (APP)

An auditable, UTXO-based privacy payment protocol on EVM chains: commitments in a Poseidon Merkle
tree, nullifiers for spends, encrypted memos for receivers, and an audit memo per output that the
registered auditor can open — proven correct inside the circuit — plus on-chain freezing.

## Principle
- AI-payment friendly
- Lightweight/aggregable on-chain verification
- Payment-focused design: no general programmability, just modular optional features
- Balanced privacy and auditability
- Cross-chain settlement capability
- Native token fee model: payment tokens can also be used to pay fees (via aggregator service)
- UTXO-based privacy payments: using commitments and nullifiers
- Merkle-tree unspent outputs with nullifier-set logging
- Auditable architecture: supports selective disclosure and asset freezing

## Layout

| dir | what |
| --- | --- |
| `payment/` | circuits (deposit, transfer m×n, withdraw), Poseidon, keys, memos, Merkle tree, EVM encoding |
| `wasm/` | browser/Node bindings: proving, memos, local tree, EVM encoding |
| `tools/` | `app-tools setup | poseidon-sol | e2e | keygen | verify-agg` |
| `solidity/` | `APP.sol`, generated Poseidon + Groth16 verifiers, `BatchVerifier`, deploy script, forge tests |
| `web/` | Vite + React wallet: deposit, transfer, withdraw, auditor view, aggregator toggle |
| `aggregator/` | axum service: verifies, batches (`submitBatch`), folds proofs with `../snarkfold` |
| `auditor/` | axum service: indexes the pool, opens audit memos, serves wallets their notes + Merkle proofs (key-authenticated) |

See `ROADMAP.md` for status and design decisions, `solidity/README.md` to deploy,
`web/README.md` to run the app, `aggregator/README.md` and `auditor/README.md` for the services.

## Quick start (local)

```sh
cargo run -p app-tools -- setup && cargo run -p app-tools -- poseidon-sol
anvil &
cargo run -p app-tools -- keygen                       # auditor key
(cd solidity && AUDITOR_X=… AUDITOR_Y=… forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 \
   --unlocked --sender 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --broadcast)
(cd web && ./scripts/sync.sh && npm i && npm run dev)  # http://localhost:5173/?dev=0
```

![APP](./app.jpg)
