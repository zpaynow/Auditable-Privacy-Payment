# APP contracts

Foundry project. `src/APP.sol` is the pool; `src/PoseidonT3.sol` and `src/verifiers/*.sol` are
generated from the Rust side and must not be edited by hand.

```
src/
  APP.sol                   pool: deposit / transfer / transfer1 / withdraw / freeze
  IncrementalMerkleTree.sol depth-20 Poseidon tree + 128-root history (mirrors Rust MerkleTree)
  PoseidonT3.sol            generated: cargo run -p app-tools -- poseidon-sol
  TestToken.sol             mintable faucet ERC20 for testnets
  verifiers/                generated: cargo run -p app-tools -- setup
test/fixtures/              generated: setup / poseidon-sol / e2e (real proofs from Rust)
script/Deploy.s.sol         deploys everything, writes deployments/<chainId>.json
script/Upgrade.s.sol        upgrades the proxy implementation / rotates verifiers
```

`APP` runs behind an ERC-1967 (UUPS) proxy. The `app` address in `deployments/<chainId>.json` is
the proxy and is the address users and services talk to; `appImpl` is only the implementation.
`PoseidonT3` and `BatchVerifier` are linked libraries deployed separately, because inlining them
puts `APP` over the 24 KB contract-size limit. Forge deploys and links them automatically through
the standard CREATE2 factory, and records their addresses under `libraries` in
`broadcast/Deploy.s.sol/<chainId>/run-latest.json`. Keep those addresses: source verification on a
block explorer needs them.

## Regenerate + test

```sh
cargo run -p app-tools -- setup          # keys -> ../artifacts, verifiers, fixtures
cargo run -p app-tools -- poseidon-sol   # PoseidonT3.sol + vectors
cargo run -p app-tools -- e2e            # coherent deposit->transfer->withdraw fixture
forge test
```

## Deploy

1. Auditor key (keep the secret offline; the web Auditor tab needs it):

   ```sh
   cargo run -p app-tools -- keygen
   ```

2. Local anvil:

   ```sh
   anvil
   AUDITOR_X=0x… AUDITOR_Y=0x… forge script script/Deploy.s.sol \
     --rpc-url http://127.0.0.1:8545 --unlocked --sender 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --broadcast
   ```

3. BOTChain Testnet (default network of the web app; chain id 968, native token BOT, explorer
   https://scan.bohr.life) — or Base Sepolia with `--rpc-url https://sepolia.base.org`. The
   script uses ~10M gas:

   ```sh
   export PK=0x…                       # funded deployer key
   export AUDITOR_X=0x… AUDITOR_Y=0x…  # from keygen
   # optional: AUDITOR_ADMIN=0x… (address allowed to freeze, default deployer)
   # optional: OPERATOR=0x…      (address allowed to call submitBatch, default deployer;
   #                              must be the aggregator's OPERATOR_KEY address)
   # optional: TOKEN=0x…         (register an existing ERC20 instead of deploying TestToken;
   #                              must be a plain ERC20: no transfer fee, no rebasing)
   # optional: OWNER=0x…         (proxy owner: may upgrade, pause and rotate verifiers;
   #                              default deployer. Use a multisig for anything valuable)
   forge script script/Deploy.s.sol --rpc-url https://rpc.bohr.life --private-key $PK --broadcast
   # verify sources (optional):
   #   forge script … --verify --etherscan-api-key $BASESCAN_KEY
   ```

   Output: `deployments/968.json` (or `84532.json` for Base Sepolia; commit it). Then `cd ../web && ./scripts/sync.sh` so the web
   app and the aggregator pick up the addresses and ABI. More operators can be added later with
   `cast send $APP "setOperator(address,bool)" $OP true`.

   `web/public/keys` must come from the very same `app-tools setup` run as the deployed
   verifiers. The setup randomness is drawn from the OS and never written down, so the keys
   cannot be reproduced afterwards: if you lose `../artifacts`, you must re-run setup and
   redeploy every verifier. Never generate deployed verifiers with `--insecure-seed`.

## Gas (via-IR, forge tests + anvil)

| operation | gas |
| --- | --- |
| deposit | 1.3M–1.6M |
| transfer 1-in/2-out, direct | 1.2M–1.3M |
| transfer 2-in/2-out, direct | 1.3M |
| withdraw, direct | 0.33M |
| submitBatch, 8 transfers (1-in/3-out) | 3.2M total, 0.40M each |
| submitBatch, 8 transfers + 2 withdraws | 3.7M total, 0.37M each |
| PoseidonT3.hash | ~45k |

Full measurements in `../ROADMAP.md` §4.
