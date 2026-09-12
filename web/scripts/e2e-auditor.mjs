// End-to-end test of the auditor-service sync path against anvil + a running auditor service.
//
//   (anvil, deploy, sync.sh; then `cd auditor && … cargo run --release`)
//   cd web && AUD=http://127.0.0.1:8788 node scripts/e2e-auditor.mjs
//
// The wallet here never scans the chain and holds no tree: it authenticates to the service with
// its payment key, gets its notes (decrypting the owner memos locally for the blinds), checks
// nullifiers, fetches Merkle proofs, and transfers / withdraws directly on-chain.
import fs from 'node:fs'
import crypto from 'node:crypto'
import { createRequire } from 'node:module'
import { createPublicClient, createWalletClient, http, defineChain } from 'viem'
import { mnemonicToAccount } from 'viem/accounts'

const require = createRequire(import.meta.url)
const w = require('../../wasm/pkg-node/wasm.js')
const ROOT = new URL('../..', import.meta.url).pathname
const RPC = process.env.RPC ?? 'http://127.0.0.1:8545'
const AUD = process.env.AUD ?? 'http://127.0.0.1:8788'
const dep = JSON.parse(fs.readFileSync(`${ROOT}web/src/deployments/31337.json`, 'utf8'))
const appAbi = JSON.parse(fs.readFileSync(`${ROOT}web/src/abi/APP.json`, 'utf8'))
const tokenAbi = JSON.parse(fs.readFileSync(`${ROOT}web/src/abi/TestToken.json`, 'utf8'))

const chain = defineChain({ id: 31337, name: 'anvil', nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [RPC] } } })
const pub = createPublicClient({ chain, transport: http(RPC) })
const MNEMONIC = 'test test test test test test test test test test test junk'
const aliceW = createWalletClient({ account: mnemonicToAccount(MNEMONIC, { addressIndex: 4 }), chain, transport: http(RPC) })
const bobAddr = mnemonicToAccount(MNEMONIC, { addressIndex: 5 }).address

const U = 10n ** 6n
const MASK = (1n << 64n) - 1n
const lo = (n) => n & MASK, hi = (n) => n >> 64n
const rnd = () => crypto.randomBytes(32)
const hex = (b) => '0x' + Buffer.from(b).toString('hex')
const hexToBuf = (h) => Buffer.from(h.slice(2), 'hex')
const be32 = (n) => hexToBuf('0x' + n.toString(16).padStart(64, '0'))
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b }
const u128le = (n) => Buffer.concat([u64le(lo(n)), u64le(hi(n))])
const words = (proofEvm) => Array.from({ length: 8 }, (_, i) => BigInt(hex(proofEvm.slice(i * 32, i * 32 + 32))))
const auditorPk = Buffer.concat([be32(BigInt(dep.auditorX)).reverse(), be32(BigInt(dep.auditorY)).reverse()])
const loadPk = (n) => fs.readFileSync(`${ROOT}artifacts/${n}.pk`)
const assert = (c, m) => { if (!c) throw new Error('assertion failed: ' + m) }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function tx(wallet, req) {
  const hash = await wallet.writeContract({ ...req, account: wallet.account, chain })
  const r = await pub.waitForTransactionReceipt({ hash })
  if (r.status !== 'success') throw new Error('reverted')
  return r
}

// ---- auditor service client (mirrors web/src/lib/auditorClient.ts)
async function api(path, init) {
  const r = await fetch(AUD + path, init)
  const j = await r.json()
  if (!r.ok) throw new Error(`${path}: ${j.error ?? r.status}`)
  return j
}
function auth(sh) {
  const ts = Math.floor(Date.now() / 1000)
  const msg = `APP-auditor-auth-v1\n31337\n${dep.app.toLowerCase()}\n${ts}`
  const sig = w.sign_message(sh.sk, Buffer.from(msg))
  return { 'X-APP-Auth': `${hex(sh.pk)}.${ts}.${hex(sig)}` }
}
async function waitIndexed() {
  const head = await pub.getBlockNumber()
  for (let i = 0; i < 30; i++) {
    const s = await api('/chains/31337/status')
    if (BigInt(s.indexed_block ?? 0) >= head) return s
    await sleep(500)
  }
  throw new Error('auditor service did not catch up')
}

class Remote {
  constructor(kp) { this.sk = kp.secret_key(); this.pk = kp.public_key(); this.utxos = [] }
  async sync() {
    await waitIndexed()
    const notes = await api('/chains/31337/notes', { headers: auth(this) })
    const known = new Set(this.utxos.map((u) => u.index))
    for (const n of notes) {
      if (known.has(n.index)) continue
      const commLe = w.fr_from_evm(hexToBuf(n.commitment))
      const dec = Buffer.from(w.owner_memo_decrypt(this.sk, commLe, hexToBuf(n.owner_memo)))
      const asset = dec.readBigUInt64LE(0), amount = dec.readBigUInt64LE(8) | (dec.readBigUInt64LE(16) << 64n), blind = dec.subarray(24, 56)
      assert(amount.toString() === n.amount, 'service amount == memo amount')
      const nullifier = hex(w.fr_to_evm(w.compute_nullifier(this.sk, asset, lo(amount), hi(amount), blind)))
      this.utxos.push({ index: n.index, asset, amount, blind, nullifier, freezer: n.freezer, spent: false })
    }
    const live = this.utxos.filter((u) => !u.spent)
    if (live.length) {
      const { spent } = await api('/chains/31337/nullifiers/check', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ nullifiers: live.map((u) => u.nullifier) }) })
      live.forEach((u, i) => (u.spent = spent[i]))
    }
    return this.utxos.filter((u) => !u.spent)
  }
  async proofsFor(indices) {
    const ps = []
    for (const i of indices) ps.push(await api(`/chains/31337/proof/${i}`, { headers: auth(this) }))
    assert(ps.every((p) => p.root === ps[0].root), 'same root')
    return { proofs: ps.map((p) => hexToBuf(p.proof)), root: ps[0].root }
  }
}

async function deposit(wallet, sh, amount) {
  const blind = w.generate_random_blind(rnd())
  const commLe = w.compute_commitment(1n, lo(amount), hi(amount), sh.pk, blind)
  const ownerMemo = w.owner_memo_encrypt(1n, lo(amount), hi(amount), sh.pk, blind, rnd())
  const ab = w.audit_memo_encrypt(1n, lo(amount), hi(amount), sh.pk, blind, auditorPk, rnd())
  const proof = w.deposit_prove(loadPk('deposit'), 1n, lo(amount), hi(amount), sh.pk, blind, auditorPk, ab.slice(0, 160), ab.slice(160), rnd())
  return tx(wallet, { address: dep.app, abi: appAbi, functionName: 'deposit', args: [1n, amount, BigInt(hex(w.fr_to_evm(commLe))), hex(ownerMemo), hex(ab.slice(0, 160)), words(w.proof_to_evm(proof))] })
}

async function transfer(wallet, sh, inputs, toPk, amount) {
  const total = inputs.reduce((s, u) => s + u.amount, 0n)
  const { proofs } = await sh.proofsFor(inputs.map((u) => u.index))
  const inBlob = Buffer.concat(inputs.map((u, i) => Buffer.concat([u64le(u.asset), u128le(u.amount), Buffer.from(u.blind), proofs[i]])))
  const outs = [{ amount, pk: toPk }, { amount: total - amount, pk: sh.pk }].map((o) => ({ ...o, blind: w.generate_random_blind(rnd()) }))
  const outBlob = Buffer.concat(outs.map((o) => Buffer.concat([u64le(1n), u128le(o.amount), Buffer.from(o.pk), Buffer.from(o.blind)])))
  const auditBlob = Buffer.concat(outs.map((o) => Buffer.from(w.audit_memo_encrypt(1n, lo(o.amount), hi(o.amount), o.pk, o.blind, auditorPk, rnd()))))
  const shape = inputs.length === 2 ? 'transfer_2x2' : 'transfer_1x2'
  const r = w.transfer_prove(loadPk(shape), sh.sk, inBlob, outBlob, auditorPk, auditBlob, rnd())
  const pw = words(hexToBuf(r.proof))
  const comms = r.commitments.map(BigInt)
  if (inputs.length === 2) return tx(wallet, { address: dep.app, abi: appAbi, functionName: 'transfer', args: [r.nullifiers.map(BigInt), r.freezers.map(BigInt), comms, BigInt(r.merkle_root), r.owner_memos, r.audit_memos, pw] })
  return tx(wallet, { address: dep.app, abi: appAbi, functionName: 'transfer1', args: [BigInt(r.nullifiers[0]), BigInt(r.freezers[0]), comms, BigInt(r.merkle_root), r.owner_memos, r.audit_memos, pw] })
}

async function withdraw(wallet, sh, u, recipient) {
  const { proofs: [mp], root } = await sh.proofsFor([u.index])
  const proof = w.withdraw_prove(loadPk('withdraw'), sh.sk, u.asset, lo(u.amount), hi(u.amount), hexToBuf(recipient), 0n, 0n, u.asset, lo(u.amount), hi(u.amount), sh.pk, u.blind, mp.subarray(0, 1280), mp.readUInt32LE(1320), mp.subarray(1280, 1312), mp.readUInt32LE(1312), mp.readUInt32LE(1316), rnd())
  return tx(wallet, { address: dep.app, abi: appAbi, functionName: 'withdraw', args: [u.asset, u.amount, BigInt(u.nullifier), BigInt(u.freezer), BigInt(root), recipient, 0n, words(w.proof_to_evm(proof))] })
}

const bal = (a) => pub.readContract({ address: dep.token, abi: tokenAbi, functionName: 'balanceOf', args: [a] })

// ------------------------------------------------------------------- flow
const status = await api('/chains/31337/status')
console.log('auditor service:', status)
assert(status.app.toLowerCase() === dep.app.toLowerCase(), 'service points at our deployment')

const alice = new Remote(new w.WasmKeypair(Buffer.from('alice-aud-' + Date.now())))
const bob = new Remote(new w.WasmKeypair(Buffer.from('bob-aud-' + Date.now())))
const A = aliceW.account.address
await tx(aliceW, { address: dep.token, abi: tokenAbi, functionName: 'mint', args: [A, 1_000n * U] })
await tx(aliceW, { address: dep.token, abi: tokenAbi, functionName: 'approve', args: [dep.app, 1_000_000n * U] })

console.log('0. unauthenticated / wrong-key requests are rejected')
let rejected = false
try { await api('/chains/31337/notes') } catch { rejected = true }
assert(rejected, 'no header -> 401')
rejected = false
try { const h = auth(alice); h['X-APP-Auth'] = h['X-APP-Auth'].replace(/.$/, (c) => (c === '0' ? '1' : '0')); await api('/chains/31337/notes', { headers: h }) } catch { rejected = true }
assert(rejected, 'tampered signature -> 401')

console.log('1. alice deposits 600 + 400, syncs through the service')
await deposit(aliceW, alice, 600n * U)
await deposit(aliceW, alice, 400n * U)
let live = await alice.sync()
assert(live.length === 2 && live.reduce((s, u) => s + u.amount, 0n) === 1000n * U, 'alice sees her 2 notes via the service')
assert((await bob.sync()).length === 0, 'bob sees nothing')

console.log('2. alice -> bob 700 (2-in), proofs from the service')
await transfer(aliceW, alice, live, bob.pk, 700n * U)
live = await alice.sync()
let bobLive = await bob.sync()
assert(live.length === 1 && live[0].amount === 300n * U, 'alice change 300, spent inputs detected via /nullifiers/check')
assert(bobLive.length === 1 && bobLive[0].amount === 700n * U, 'bob received 700')

console.log('3. bob withdraws 700, proof from the service')
const before = await bal(bobAddr)
await withdraw(aliceW, bob, bobLive[0], bobAddr)
assert((await bal(bobAddr)) - before === 700n * U, 'bob public +700')
bobLive = await bob.sync()
assert(bobLive.length === 0, 'bob note spent')

console.log('4. admin view lists everything')
const all = await api('/chains/31337/audit/notes?limit=1000', { headers: { 'x-admin-token': process.env.ADMIN_TOKEN ?? 'dev' } })
const mine = all.filter((n) => n.owner === hex(alice.pk) || n.owner === hex(bob.pk))
assert(mine.length === 4, `auditor attributes 4 notes to alice/bob (got ${mine.length})`)
console.log('  total notes indexed:', all.length)

console.log('\nALL GOOD')
