# APP web

Browser wallet for Auditable Privacy Payment. Proofs are generated in a Web Worker with the
`wasm` crate; the page talks to the `APP` contract through wagmi/viem.

## Run locally (anvil)

```sh
# 1. chain + contracts
anvil &
cargo run -p app-tools -- keygen            # auditor key; keep the secret, pass x/y below
cd solidity && AUDITOR_X=0x… AUDITOR_Y=0x… forge script script/Deploy.s.sol \
  --rpc-url http://127.0.0.1:8545 --unlocked --sender 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --broadcast
cd ..

# 2. web assets (wasm, proving keys, ABIs, deployment addresses)
cd web && ./scripts/sync.sh && npm install

# 3. dev server
npm run dev
```

Open <http://localhost:5173/> with MetaMask on the "Anvil (local)" network, or skip the extension
entirely with the built-in dev wallet. `?dev=N` uses anvil account N (0 is the deployer and
auditor admin); `?devkey=0x…` uses an explicit private key. Open two tabs with `?dev=0` and
`?dev=1` to pay yourself.

```
http://localhost:5173/?dev=0
```

Tabs: **Deposit** (mint faucet tokens, shield), **Transfer** (send to a payment address),
**Withdraw** (unshield one note), **Auditor** (paste the auditor secret, open every note, freeze).

## Auditor service (no chain scanning)

If `auditor/` is running for the current chain (`VITE_AUDITOR_URL`, default
`http://127.0.0.1:8788`) the wallet fetches its notes and Merkle proofs from it, authenticated
with a Schnorr signature by the payment key; the balance card shows "via auditor service".
Otherwise it scans `NewCommitment` events itself and keeps a local tree ("from chain").

## Aggregator (Phase 2)

Start `aggregator/` (see its README) and the Transfer / Withdraw tabs offer "through the
aggregator": no wallet transaction, the fee is paid inside the pool. Set `VITE_AGGREGATOR_URL`
if the service is not on `http://127.0.0.1:8787`.

## Headless end-to-end

Same wasm and contracts, driven from Node against anvil:

```sh
AUDITOR_SECRET=0x… node scripts/e2e-anvil.mjs        # direct path
AGGREGATOR_SECRET=0x… node scripts/e2e-aggregator.mjs # via the running aggregator
ADMIN_TOKEN=dev node scripts/e2e-auditor.mjs          # sync through the auditor service
```

## Testnet

Deploy with a funded key (`--private-key`) and the testnet RPC (see `solidity/README.md`), then
rerun `scripts/sync.sh`; the app picks up `src/deployments/<chainId>.json` automatically and
offers the chain in the network selector. For a hosted build set `VITE_AGGREGATOR_URL` to the
public aggregator URL before `npm run build`. Proving keys in `public/keys`
(25 MB) should move to a CDN for a public deployment.
