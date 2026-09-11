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

## Headless end-to-end

Same wasm and contracts, driven from Node against anvil:

```sh
AUDITOR_SECRET=0x… node scripts/e2e-anvil.mjs
```

## Testnet

Deploy with a funded key (`--private-key`) and the testnet RPC, then rerun `scripts/sync.sh`;
the app picks up `src/deployments/<chainId>.json` automatically. Proving keys in `public/keys`
(25 MB) should move to a CDN for a public deployment.
