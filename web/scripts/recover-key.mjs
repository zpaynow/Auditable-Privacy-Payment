// Recover a payment key that the app can no longer re-derive.
//
// The web app derives the shielded key from an EVM signature over a message that embeds the
// chain id AND the pool contract address. Redeploying the pool therefore changes the message and
// so changes the payment key, while a key already held in sessionStorage keeps being used against
// the new pool. Notes created in that window belong to the older key and become invisible once
// the tab is closed and the key is derived again.
//
// This tries every (chain, contract) message this repo has ever deployed, plus the usual
// byte-level variants of a signature, and reports which one reproduces a target address.
//
//   cd web
//   PRIVATE_KEY=0x… node scripts/recover-key.mjs <targetAddress>     # signs locally
//   SIG=0x…        node scripts/recover-key.mjs <targetAddress> 677  # or bring your own signature
//
// Nothing is sent anywhere; the key and signature stay in this process.
import fs from 'node:fs'
import { createRequire } from 'node:module'
import { privateKeyToAccount } from 'viem/accounts'
const require = createRequire(import.meta.url)
const w = require('../../wasm/pkg-node/wasm.js')

const TARGET = (process.argv[2] ?? '').toLowerCase()
if (!TARGET.startsWith('0x')) throw new Error('usage: PRIVATE_KEY=0x… node scripts/recover-key.mjs <targetAddress>')
const ONLY_CHAIN = process.argv[3] ? Number(process.argv[3]) : null

const MSG = (chainId, app) =>
  `Auditable Privacy Payment\n\nSign to derive your private payment key.\nchain: ${chainId}\ncontract: ${app.toLowerCase()}\n\nThis signature never leaves your browser.`

// Every pool this repo has pointed at, current and superseded.
const POOLS = [
  [677, '0xce1258E3A9542a09BCf820E2F019aAfB0D1148BB', '677 当前池'],
  [677, '0xc4276f018531Ee45D17f2d8F3E45547A4A8e1c61', '677 旧池（已作废）'],
  [968, '0xA1e792aD97F389a73e44f13352CC371f63E1ef78', '968 当前池'],
  [968, '0x5930c88c589d5F5beAe3963Ae19a5D7675Bd8B49', '968 旧池（已作废）'],
]
for (const f of fs.readdirSync(new URL('../src/deployments', import.meta.url))) {
  const d = JSON.parse(fs.readFileSync(new URL(`../src/deployments/${f}`, import.meta.url), 'utf8'))
  if (!POOLS.some(([c, a]) => c === d.chainId && a.toLowerCase() === d.app.toLowerCase())) {
    POOLS.push([d.chainId, d.app, `${d.chainId} 部署文件`])
  }
}

const account = process.env.PRIVATE_KEY ? privateKeyToAccount(process.env.PRIVATE_KEY) : null
if (account) console.log(`用 EVM 账号 ${account.address} 在本地签名\n`)
else if (!process.env.SIG) throw new Error('set PRIVATE_KEY (signs locally) or SIG (a signature you already have)')

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
function variants(sigHex) {
  const raw = Buffer.from(sigHex.replace(/^0x/, ''), 'hex')
  const rs = raw.subarray(0, 64)
  const out = [['原样', raw]]
  if (raw.length === 65) {
    for (const v of [0x00, 0x01, 0x1b, 0x1c]) if (v !== raw[64]) out.push([`v=0x${v.toString(16)}`, Buffer.concat([rs, Buffer.of(v)])])
    out.push(['仅 r||s', rs])
  }
  const s = BigInt('0x' + rs.subarray(32, 64).toString('hex'))
  if (s > N / 2n) out.push(['low-s', Buffer.concat([rs.subarray(0, 32), Buffer.from((N - s).toString(16).padStart(64, '0'), 'hex'), raw.subarray(64)])])
  return out
}

const addrOf = (seed) => {
  try { return '0x' + Buffer.from(w.compress_pk(new w.WasmKeypair(seed).public_key())).toString('hex') }
  catch { return null }
}

console.log('链  合约                                        变体      派生出的支付地址')
let hit = null
for (const [chainId, app, label] of POOLS) {
  if (ONLY_CHAIN && chainId !== ONLY_CHAIN) continue
  const sig = account ? await account.signMessage({ message: MSG(chainId, app) }) : process.env.SIG
  for (const [vname, seed] of variants(sig)) {
    const a = addrOf(seed)
    if (!a) continue
    const match = a === TARGET
    if (match) hit = { chainId, app, label, vname, seed }
    if (match || vname === '原样') console.log(`${String(chainId).padEnd(4)}${app}  ${vname.padEnd(8)}  ${a}${match ? '  <== 命中' : ''}`)
  }
  if (!account) break // a supplied signature only corresponds to one message
}
console.log()
if (hit) {
  const kp = new w.WasmKeypair(hit.seed)
  console.log(`命中：${hit.label}，消息里的合约是 ${hit.app}，签名变体「${hit.vname}」。`)
  console.log('这把支付密钥的 32 字节私钥：')
  console.log('  0x' + Buffer.from(kp.secret_key()).toString('hex'))
  console.log('\n在网页上恢复该身份：打开控制台执行')
  console.log('  sessionStorage.setItem("app.zk.secret", "0x' + Buffer.from(kp.secret_key()).toString('hex') + '")')
  console.log('然后刷新页面，这把身份下的票据就会出现，可以正常花费。')
} else {
  console.log('所有链、所有历史合约地址、所有签名变体都无法复现目标地址。')
  console.log('说明这把密钥不是由该 EVM 账号按当前规则派生的，或钱包的签名本身不可复现。')
}
