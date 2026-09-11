# wasm bindings

Browser/Node bindings over `app-payment`: keys, memos, local Merkle tree, Groth16 proving and EVM encoding.

```sh
# browser build (ES module) -> wasm/pkg
wasm-pack build --release --target web --out-dir pkg

# node build + end-to-end smoke test (needs artifacts/*.pk from `cargo run -p app-tools -- setup`)
wasm-pack build --release --target nodejs --out-dir pkg-node
node tests/smoke.mjs
```

Byte conventions: field elements are 32-byte arkworks little-endian unless a function name says `evm`
(big-endian `bytes32`). Public keys are `x || y` (64 bytes). Amounts are `u128` passed as two `u64`s.
Merkle proof blob = nodes (20 × 64) || root (32) || version (4 LE) || index (4 LE) || ledger (4 LE).
