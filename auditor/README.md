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

## Run

```sh
cp auditor/.env.example auditor/.env   # APP_ADDRESS, AUDITOR_SECRET, DEPLOY_BLOCK (from deployments/<chainId>.json)
cd auditor && cargo run --release
```

The web app uses the service automatically when `GET /status` answers for the current chain and
contract, and falls back to scanning the chain otherwise. Configure the URL with
`VITE_AUDITOR_URL` (default `http://127.0.0.1:8788`). Set `ADMIN_TOKEN` to enable the full
decrypted view for the auditor UI.

## API

| method | path | auth | response |
| --- | --- | --- | --- |
| GET | `/status` | – | chain, contract, indexed block, counts, current root |
| GET | `/auth/message` | – | the string to sign for the current time |
| GET | `/notes` | payment key | notes owned by the caller: index, commitment, owner/audit memo, asset, amount, freezer, frozen |
| GET | `/proof/:index` | payment key | Merkle proof blob (`MTProof::to_bytes`) + root |
| POST | `/nullifiers/check` | – | `{nullifiers: [..]}` → `{spent: [..]}` (≤ 1000) |
| GET | `/audit/notes?offset&limit` | `X-Admin-Token` | every note, decrypted |

Auth header: `X-APP-Auth: <pk 64B hex>.<unix ts>.<sig 64B hex>` where sig = Schnorr over
`"APP-auditor-auth-v1\n{chainId}\n{app lowercase}\n{ts}"` (`wasm.sign_message`).

## Test

```sh
cd auditor && APP_ADDRESS=… AUDITOR_SECRET=… DEPLOY_BLOCK=… ADMIN_TOKEN=dev cargo run --release
cd web && ADMIN_TOKEN=dev node scripts/e2e-auditor.mjs
```

## Notes

- Indexing is strictly sequential by commitment index; a gap aborts the poll and retries.
- The tree is rebuilt from SQLite at startup; the database can be deleted and re-indexed.
- Proofs for a multi-input transfer are fetched one by one; the client retries if the root moved
  in between (a new batch landed).
