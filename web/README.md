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

Tabs: **Deposit** (get test tokens, shield), **Transfer** (send to a payment address),
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

## Deploy to Cloudflare Pages

The build needs the generated inputs (`src/wasm`, `src/abi`, `src/deployments`, `public/keys`),
which come from the Rust toolchain via `scripts/sync.sh`. Pages' build image has no Rust /
wasm-pack / forge, so build locally and upload `dist`:

```sh
./scripts/sync.sh                                   # after the Base Sepolia deploy
cp .env.example .env.production                     # set VITE_AGGREGATOR_URL / VITE_AUDITOR_URL (https!)
npx wrangler login
npx wrangler pages project create app-web --production-branch main   # once
npm run deploy                                      # = vite build + wrangler pages deploy dist
```

Settings that matter:

| what | value |
| --- | --- |
| `VITE_AGGREGATOR_URL`, `VITE_AUDITOR_URL` | public **https** URLs of the two services (a Pages site is https; http calls are blocked as mixed content). Put them behind Cloudflare Tunnel, Caddy or nginx with TLS. Both services already send permissive CORS. |
| `VITE_KEYS_URL` | leave `/keys` to ship the ~50 MB of proving keys with the site (every file is under Pages' 25 MiB limit; `public/_headers` marks them immutable). Or upload `artifacts/*.pk` to an R2 bucket with a public domain and CORS for the site origin, and set the bucket URL here. |
| `src/deployments/84532.json` | present after `sync.sh`; the app only offers chains that have a deployment file |
| Node | 22+ (Vite 8) if you ever build on Pages' side |

Git-integrated builds are possible only if you commit the generated inputs (`src/wasm`,
`src/abi`, `src/deployments`; keys via R2), set root directory `web`, build command
`npm ci && npm run build`, output `dist`, and the `VITE_*` variables in the project settings.

The dev wallet (`?dev=` / `?devkey=`) targets a local anvil and is irrelevant in production;
users connect MetaMask on Base Sepolia.

## Testnet

The default network is **BOTChain Testnet** (chain id 968, RPC `https://rpc.bohr.life`, native
token BOT, explorer `https://scan.bohr.life`); Base Sepolia is offered as well, and the local
anvil chain only in dev builds. A chain appears in the selector only when
`src/deployments/<chainId>.json` exists. Token symbol and decimals are read from the registered
ERC20. On BOTChain the deposit tab links to the external faucet
(`https://faucet.botchain.ai/en/basic`, see `faucets` in `src/lib/config.ts`); on chains without
an entry it mints the deployed `TestToken` directly.

Deploy with a funded key (`--private-key`) and the testnet RPC (see `solidity/README.md`), then
rerun `scripts/sync.sh`; the app picks up `src/deployments/<chainId>.json` automatically and
offers the chain in the network selector. For a hosted build set `VITE_AGGREGATOR_URL` to the
public aggregator URL before `npm run build`. Proving keys in `public/keys`
(25 MB) should move to a CDN for a public deployment.
