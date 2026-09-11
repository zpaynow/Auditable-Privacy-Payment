# APP aggregator

Rust service (axum + alloy) that settles shielded transactions on behalf of users:

1. `POST /tx/transfer` / `POST /tx/withdraw` — the browser submits a proof plus public data.
   The service verifies the Groth16 proof natively with the same public inputs the contract
   will derive, checks the root is known, the nullifiers unspent, the notes unfrozen, and the fee:
   - transfers use the 3-output shapes (`2x3`, `1x3`); output #2 must be a note owned by the
     aggregator's payment key worth at least `TRANSFER_FEE` of `FEE_ASSET` (checked by decrypting
     its owner memo),
   - withdraws must carry `fee >= WITHDRAW_FEE`; the contract pays it to the operator.
2. Every `BATCH_INTERVAL_SECS` (or as soon as `BATCH_MAX` are queued) the batcher re-checks the
   queue against the chain and calls `APP.submitBatch`, which verifies all proofs with one
   random-linear-combination pairing check and inserts all outputs with one tree update.
3. After confirmation the batch's proofs are folded per circuit with `snarkfold` and served at
   `GET /batch/:id/proof/:group`; auditors verify with `app-tools verify-agg`.

Every op in a batch must reference a root that was known before the batch; a transfer that
spends an output created in the same batch is queued for the next one.

## Run

```sh
cargo run -p app-tools -- keygen          # payment key for fee notes -> AGGREGATOR_SECRET
cp aggregator/.env.example aggregator/.env  # fill in APP_ADDRESS, OPERATOR_KEY, AGGREGATOR_SECRET
cd aggregator && cargo run --release
```

For a testnet set `RPC_URL=https://sepolia.base.org`, `APP_ADDRESS` from
`solidity/deployments/84532.json`, and fund the operator with test ETH (each batch costs
0.5–4M gas). The operator address must be whitelisted (`APP.setOperator`; the deploy script whitelists the
deployer, or set `OPERATOR` when deploying). Point the web app at the service with
`VITE_AGGREGATOR_URL` (default `http://127.0.0.1:8787`).

## API

| method | path | body / response |
| --- | --- | --- |
| GET | `/info` | chain, contract, operator, `aggregator_pk` (64 B x‖y LE), fees, batching params, pending count |
| POST | `/tx/transfer` | `{shape, proof, nullifiers[], freezers[], commitments[3], root, owner_memos[3], audit_memos[3]}` → `{id}` |
| POST | `/tx/withdraw` | `{proof, asset, amount, nullifier, freezer, root, recipient, fee}` → `{id}` |
| GET | `/tx/:id` | `{status: pending|submitted|confirmed|failed, batch_id, tx_hash, error}` |
| GET | `/batch/:id` | batch row + list of aggregated proofs |
| GET | `/batch/:id/proof/:group` | raw `snarkfold::AggregatedProof` bytes (`transfer_2x3`, `transfer_1x3`, `withdraw`) |

Hex values are `0x`-prefixed; amounts are decimal strings (u128); proofs are the 256-byte EVM encoding.

## Test

```sh
# anvil + deploy + web/scripts/sync.sh as in web/README.md, then:
cd aggregator && APP_ADDRESS=… OPERATOR_KEY=… AGGREGATOR_SECRET=… BATCH_INTERVAL_SECS=5 cargo run --release
cd web && AGGREGATOR_SECRET=… node scripts/e2e-aggregator.mjs
cargo run -p app-tools -- verify-agg --group transfer_2x3 --proof <downloaded proof>
```

## Notes

- Failed batches (`submitBatch` reverted) mark every tx in the batch `failed`; the pre-checks
  make this rare, and users can simply resubmit.
- Fee notes accumulate under the aggregator key; spend them with the web app by deriving the key
  from `AGGREGATOR_SECRET` (`WasmKeypair.from_secret`).
- Batching is where the gas saving is: one batch of 2 transfers + 1 withdraw costs ~2.3M gas
  versus ~3.1M sent separately, and the Poseidon tree update is shared across all outputs.
