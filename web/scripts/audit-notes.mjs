// Who owns what: opens every audit memo with the auditor key and prints the full note table.
//
//   cd web && AUDITOR_SECRET=0x… node scripts/audit-notes.mjs [chainId] [address…]
//
// The audit memo is the only authoritative answer to "whose note is this": the transfer and
// deposit circuits prove that it encrypts the real owner of each output, so it cannot lie, while
// an owner memo is only calldata. Any address given after the chain id is labelled in the output.
// The secret is read from the environment and never printed.
import fs from 'node:fs'
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
const w = require('../../wasm/pkg-node/wasm.js')

const ROOT = new URL('../..', import.meta.url).pathname
const CHAIN = Number(process.argv[2] ?? 677)
const LABELS = process.argv.slice(3)
const RPCS = { 677: 'https://rpc.botchain.ai', 968: 'https://rpc.bohr.life', 31337: 'http://127.0.0.1:8545' }
const RPC = process.env.RPC ?? RPCS[CHAIN]
if (!RPC) throw new Error(`no RPC for chain ${CHAIN}; set RPC=…`)
const SECRET = process.env.AUDITOR_SECRET
if (!SECRET) throw new Error('set AUDITOR_SECRET (32-byte LE hex from `app-tools keygen`)')

const dep = JSON.parse(fs.readFileSync(`${ROOT}web/src/deployments/${CHAIN}.json`, 'utf8'))
const hexToBuf = (h) => Buffer.from(h.replace(/^0x/, ''), 'hex')
const hx = (b) => '0x' + Buffer.from(b).toString('hex')
const rpc = async (method, params) =>
  (await (await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) })).json()).result

// Refuse to run with a key that is not the auditor of this pool: otherwise every memo decrypts
// to garbage and the table would be confidently wrong.
const kp = w.WasmKeypair.from_secret(hexToBuf(SECRET))
const apk = kp.public_key()
const onchainX = BigInt(dep.auditorX), onchainY = BigInt(dep.auditorY)
const mine = { x: BigInt(hx(w.fr_to_evm(apk.slice(0, 32)))), y: BigInt(hx(w.fr_to_evm(apk.slice(32)))) }
if (mine.x !== onchainX || mine.y !== onchainY) {
  throw new Error(`AUDITOR_SECRET is not the auditor of chain ${CHAIN} (public key does not match the deployment)`)
}

const logs = await rpc('eth_getLogs', [{ address: dep.app, fromBlock: '0x' + Number(dep.deployBlock).toString(16), toBlock: 'latest' }])
const notes = []
for (const l of logs) {
  // NewCommitment is the only event with an indexed uint32 index and two dynamic byte fields
  if (l.topics.length !== 2 || l.data.length < 2 + 64 * 6) continue
  const d = l.data.slice(2)
  const word = (i) => d.slice(i * 64, i * 64 + 64)
  const commitment = '0x' + word(0)
  const oo = parseInt(word(1), 16) / 32, ao = parseInt(word(2), 16) / 32
  const olen = parseInt(word(oo), 16), alen = parseInt(word(ao), 16)
  if (olen !== 104 || alen !== 160) continue
  const auditMemo = d.slice((ao + 1) * 64, (ao + 1) * 64 + alen * 2)
  let dec
  try { dec = Buffer.from(w.audit_memo_decrypt(hexToBuf(SECRET), Buffer.from(auditMemo, 'hex'))) }
  catch { notes.push({ index: parseInt(l.topics[1], 16), commitment, bad: true }); continue }
  const amount = dec.readBigUInt64LE(8) | (dec.readBigUInt64LE(16) << 64n)
  const ownerPk = dec.subarray(24, 88)
  notes.push({
    index: parseInt(l.topics[1], 16),
    commitment,
    asset: dec.readBigUInt64LE(0),
    amount,
    address: hx(w.compress_pk(ownerPk)),
    freezer: hx(w.fr_to_evm(w.freezer_of(w.fr_from_evm(hexToBuf(commitment)), ownerPk.subarray(0, 32)))),
  })
}
notes.sort((a, b) => a.index - b.index)

// A note is spent when its freezer turns up in the calldata of some pool transaction. Every
// spend emits NewNullifier, so the transactions behind these logs cover all of them, and matching
// on the raw 32-byte word works for every entry point including submitBatch.
const txs = [...new Set(logs.map((l) => l.transactionHash))]
const blob = (await Promise.all(txs.map((h) => rpc('eth_getTransactionByHash', [h])))).map((t) => t.input).join('')
for (const n of notes) if (n.freezer) n.spent = blob.includes(n.freezer.slice(2))

const label = (a) => {
  const i = LABELS.findIndex((x) => x.toLowerCase() === a.toLowerCase())
  return i >= 0 ? `  <-- 第 ${i + 1} 个地址` : ''
}
const U = (n) => (Number(n) / 1e6).toFixed(6)
console.log(`chain ${CHAIN}  pool ${dep.app}  共 ${notes.length} 张票据\n`)
console.log('idx  状态    金额        所有者地址')
for (const n of notes) {
  if (n.bad) { console.log(`${String(n.index).padEnd(4)} 审计备忘录解不开  ${n.commitment}`); continue }
  console.log(`${String(n.index).padEnd(4)} ${(n.spent ? '已花费' : '未花费').padEnd(7)} ${U(n.amount).padStart(11)}  ${n.address}${label(n.address)}`)
}
const live = notes.filter((n) => !n.bad && !n.spent)
const bal = new Map()
for (const n of live) bal.set(n.address, (bal.get(n.address) ?? 0n) + n.amount)
console.log('\n未花费余额（按所有者）')
for (const [a, v] of [...bal].sort((x, y) => (y[1] > x[1] ? 1 : -1))) console.log(`  ${U(v).padStart(11)}  ${a}${label(a)}`)
console.log(`  ${'-'.repeat(11)}`)
console.log(`  ${U([...bal.values()].reduce((s, v) => s + v, 0n)).padStart(11)}  合计（应等于池内代币余额）`)
