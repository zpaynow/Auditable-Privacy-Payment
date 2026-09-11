#!/usr/bin/env bash
# Pull everything the web app needs from the rest of the repo:
#   - wasm bindings  -> src/wasm/        (wasm-pack, web target)
#   - proving keys   -> public/keys/     (from artifacts/, produced by `app-tools setup`)
#   - ABIs           -> src/abi/         (from forge out/)
#   - deployments    -> src/deployments/ (from solidity/deployments/<chainId>.json)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WEB="$ROOT/web"

echo "• building wasm"
(cd "$ROOT/wasm" && wasm-pack build --release --target web --out-dir "$WEB/src/wasm" >/dev/null)
rm -f "$WEB/src/wasm/.gitignore" "$WEB/src/wasm/package.json" "$WEB/src/wasm/README.md"

echo "• copying proving keys"
mkdir -p "$WEB/public/keys"
cp "$ROOT"/artifacts/*.pk "$ROOT"/artifacts/*.vk "$WEB/public/keys/"

echo "• building contracts + copying ABIs"
(cd "$ROOT/solidity" && forge build >/dev/null)
mkdir -p "$WEB/src/abi"
for c in APP TestToken; do
  node -e "const a=require('$ROOT/solidity/out/$c.sol/$c.json');require('fs').writeFileSync('$WEB/src/abi/$c.json',JSON.stringify(a.abi,null,1))"
done

echo "• copying deployments"
mkdir -p "$WEB/src/deployments"
cp "$ROOT"/solidity/deployments/*.json "$WEB/src/deployments/" 2>/dev/null || echo "  (no deployments yet)"
ls "$WEB/src/deployments"
echo "done"
