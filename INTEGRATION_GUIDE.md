# SnarkFold integration (Phase 2)

`../snarkfold` aggregates Groth16 proofs **per verifying key** into one relaxed pair plus a
transcript. In this project it is used by the aggregator service, off-chain:

- For every batch the service folds the transfer / withdraw proofs it submitted, grouped by
  circuit shape, and publishes the `AggregatedProof` at `GET /batch/:id`.
- Auditors and light clients verify a batch with `verify_aggregated(vk, &agg)` (3 pairings + one
  GT exponentiation per fold step) instead of re-verifying every Groth16 proof.
- The **on-chain** contract does not use SnarkFold: the relaxed relation compares against an
  arbitrary GT element, which the EVM pairing precompile cannot do. `APP.submitBatch` verifies
  the batch with a random-linear-combination Groth16 check instead (n + 3·groups pairings).

```rust
use snarkfold::*;
let gvk = GrothVerifyingKey::from_ark_vk(&transfer_vk);
let mut agg = Aggregator::new(&gvk);
for tx in batch.transfers_2x3 {
    agg.push(&Instance { public_inputs: tx.publics.clone() }, &Proof::from(tx.proof.clone()))?;
}
let proof = agg.finish();
```
