# APP auditor service

Indexer + API run by the auditor. It follows the pool's events, opens every audit memo with the
auditor key (owner, asset, amount), keeps the commitment tree, and lets wallets fetch their own
notes and Merkle proofs — so the browser neither scans the chain nor holds the tree.

What the service knows and what it does not:

- It knows which payment key owns every note (that is the auditor's role by design).
- It does **not** know the blinds, so it cannot spend or compute nullifiers. Wallets decrypt the
  owner memos locally and check spent status with `POST /nullifiers/check`.
- A wallet must prove it holds the payment key before the service lists that key's notes
  (Schnorr signature on BabyJubJub, `X-APP-Auth` header, 5-minute window), so knowing someone's
  payment address does not reveal their balance.

## Run (multi-chain)

One instance serves every chain that has a deployment file in `DEPLOYMENTS_DIR`
(`solidity/deployments/<chainId>.json`). Per-chain settings use a `_<chainId>` suffix and fall
back to the unsuffixed variable; see `.env.example`.

```sh
cp auditor/.env.example auditor/.env   # RPC_URL_<id>, AUDITOR_SECRET[_<id>], ADMIN_TOKEN
cd auditor && cargo run --release
```

The auditor secret must match `auditorX/Y` in the deployment file (the service warns at startup
if it does not). Restrict the served chains with `CHAINS=…`. The web app uses the service
automatically when `GET /chains/{chainId}/status` answers for the current chain and contract,
and falls back to scanning the chain otherwise (`VITE_AUDITOR_URL`, default
`http://127.0.0.1:8788`). Set `ADMIN_TOKEN` to enable the full decrypted view.

## API

All routes are scoped to a chain: `/chains/{chainId}/…`. `GET /chains` lists the served chains.

| method | path | auth | response |
| --- | --- | --- | --- |
| GET | `/chains` | – | served chains with contract, indexed block, note count |
| GET | `/chains/{id}/status` | – | contract, indexed block, counts, current root |
| GET | `/chains/{id}/auth/message` | – | the string to sign for the current time |
| GET | `/chains/{id}/notes` | payment key | notes owned by the caller: index, commitment, owner/audit memo, asset, amount, freezer, frozen |
| GET | `/chains/{id}/proof/:index` | payment key | Merkle proof blob (`MTProof::to_bytes`) + root |
| POST | `/chains/{id}/nullifiers/check` | – | `{nullifiers: [..]}` → `{spent: [..]}` (≤ 1000) |
| GET | `/chains/{id}/audit/notes?offset&limit` | `X-Admin-Token` | every note, decrypted |

Auth header: `X-APP-Auth: <pk 64B hex>.<unix ts>.<sig 64B hex>` where sig = Schnorr over
`"APP-auditor-auth-v1\n{chainId}\n{app lowercase}\n{ts}"` (`wasm.sign_message`). The chain id
and contract address are part of the signed string, so a signature is valid for one chain only.

## Test

```sh
cd auditor && DEPLOYMENTS_DIR=../solidity/deployments CHAINS=31337 RPC_URL_31337=http://127.0.0.1:8545 \
  AUDITOR_SECRET=… ADMIN_TOKEN=dev cargo run --release
cd web && ADMIN_TOKEN=dev node scripts/e2e-auditor.mjs
```

## Notes

- Indexing is strictly sequential by commitment index; a gap aborts the poll and retries.
- The tree is rebuilt from SQLite at startup; the database can be deleted and re-indexed.
- Proofs for a multi-input transfer are fetched one by one; the client retries if the root moved
  in between (a new batch landed).
