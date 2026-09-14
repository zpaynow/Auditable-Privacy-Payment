// End-to-end test of the aggregator path against anvil + a running aggregator service.
//
//   (anvil, deploy, sync.sh as in e2e-anvil.mjs)
//   cd aggregator && APP_ADDRESS=… OPERATOR_KEY=… AGGREGATOR_SECRET=… BATCH_INTERVAL_SECS=5 cargo run --release
//   cd web && AGG=http://127.0.0.1:8787 node scripts/e2e-aggregator.mjs
//
// alice deposits 600 + 400 directly, then sends 500 to bob THROUGH the aggregator (2-in/3-out,
// third output = fee note), bob withdraws 500 through the aggregator (fee field), and we read
// the batch + aggregated SnarkFold proofs back from the service.
import fs from 'node:fs'
import crypto from 'node:crypto'
import { createRequire } from 'node:module'
import { createPublicClient, createWalletClient, http, parseAbiItem, defineChain } from 'viem'
import { mnemonicToAccount } from 'viem/accounts'

const require = createRequire(import.meta.url)
const w = require('../../wasm/pkg-node/wasm.js')
const ROOT = new URL('../..', import.meta.url).pathname
const RPC = process.env.RPC ?? 'http://127.0.0.1:8545'
const AGG = process.env.AGG ?? 'http://127.0.0.1:8787'
const dep = JSON.parse(fs.readFileSync(`${ROOT}web/src/deployments/31337.json`, 'utf8'))
const appAbi = JSON.parse(fs.readFileSync(`${ROOT}web/src/abi/APP.json`, 'utf8'))
const tokenAbi = JSON.parse(fs.readFileSync(`${ROOT}web/src/abi/TestToken.json`, 'utf8'))

const chain = defineChain({ id: 31337, name: 'anvil', nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [RPC] } } })
const pub = createPublicClient({ chain, transport: http(RPC) })
const MNEMONIC = 'test test test test test test test test test test test junk'
const aliceW = createWalletClient({ account: mnemonicToAccount(MNEMONIC, { addressIndex: 2 }), chain, transport: http(RPC) })
const bobAddr = mnemonicToAccount(MNEMONIC, { addressIndex: 3 }).address

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
async function api(path, body) {
  const r = await fetch(AGG + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {})
  const j = await r.json()
  if (!r.ok) throw new Error(`${path}: ${j.error ?? r.status}`)
  return j
}
async function waitTx(id) {
  for (let i = 0; i < 120; i++) {
    const s = await api(`/chains/31337/tx/${id}`)
    if (s.status === 'confirmed') return s
    if (s.status === 'failed') throw new Error(`tx ${id} failed: ${s.error}`)
    await sleep(1000)
  }
  throw new Error('timeout waiting for batch')
}

class Shielded {
  constructor(kp) { this.sk = kp.secret_key(); this.pk = kp.public_key(); this.tree = new w.WasmMerkleTree(0); this.n = 0; this.utxos = [] }
  async sync() {
    const head = await pub.getBlockNumber()
    const logs = await pub.getLogs({ address: dep.app, event: parseAbiItem('event NewCommitment(uint32 indexed index, uint256 commitment, bytes ownerMemo, bytes auditMemo)'), fromBlock: BigInt(dep.deployBlock), toBlock: head })
    logs.sort((a, b) => Number(a.args.index) - Number(b.args.index))
    let added = false
    for (const l of logs) {
      const idx = Number(l.args.index)
      if (idx < this.n) continue
      if (idx !== this.n) throw new Error('index gap')
      const commLe = w.fr_from_evm(be32(l.args.commitment))
      this.tree.add_leaf(commLe); this.n++; added = true
      try {
        const dec = Buffer.from(w.owner_memo_decrypt(this.sk, commLe, hexToBuf(l.args.ownerMemo)))
        const asset = dec.readBigUInt64LE(0), amount = dec.readBigUInt64LE(8) | (dec.readBigUInt64LE(16) << 64n), blind = dec.subarray(24, 56)
        const nullifier = hex(w.fr_to_evm(w.compute_nullifier(this.sk, asset, lo(amount), hi(amount), blind)))
        const freezer = hex(w.fr_to_evm(w.freezer_of(commLe, this.pk.slice(0, 32))))
        this.utxos.push({ index: idx, asset, amount, blind, nullifier, freezer, spent: false })
      } catch { /* not ours */ }
    }
    if (added) this.tree.commit()
    const nl = await pub.getLogs({ address: dep.app, event: parseAbiItem('event NewNullifier(uint256 nullifier)'), fromBlock: 0n, toBlock: head })
    const set = new Set(nl.map((l) => hex(be32(l.args.nullifier))))
    for (const u of this.utxos) u.spent = set.has(u.nullifier)
    return this.utxos.filter((u) => !u.spent)
  }
  root() { return hex(this.tree.root_evm()) }
}

async function deposit(wallet, sh, amount) {
  const blind = w.generate_random_blind(rnd())
  const commLe = w.compute_commitment(1n, lo(amount), hi(amount), sh.pk, blind)
  const ownerMemo = w.owner_memo_encrypt(1n, lo(amount), hi(amount), sh.pk, blind, rnd())
  const ab = w.audit_memo_encrypt(1n, lo(amount), hi(amount), sh.pk, blind, auditorPk, rnd())
  const proof = w.deposit_prove(loadPk('deposit'), 1n, lo(amount), hi(amount), sh.pk, blind, ownerMemo, auditorPk, ab.slice(0, 160), ab.slice(160), rnd())
  return tx(wallet, { address: dep.app, abi: appAbi, functionName: 'deposit', args: [1n, amount, BigInt(hex(w.fr_to_evm(commLe))), hex(ownerMemo), hex(ab.slice(0, 160)), words(w.proof_to_evm(proof))] })
}

/// 3-output transfer via the aggregator: [to, change, fee -> aggregator]
async function transferViaAggregator(sh, inputs, toPk, amount, info) {
  const fee = BigInt(info.transfer_fee)
  const aggPk = hexToBuf(info.aggregator_pk)
  const total = inputs.reduce((s, u) => s + u.amount, 0n)
  const inBlob = Buffer.concat(inputs.map((u) => Buffer.concat([u64le(u.asset), u128le(u.amount), Buffer.from(u.blind), Buffer.from(sh.tree.proof(u.index))])))
  const outs = [{ amount, pk: toPk }, { amount: total - amount - fee, pk: sh.pk }, { amount: fee, pk: aggPk }].map((o) => ({ ...o, blind: w.generate_random_blind(rnd()) }))
  const outBlob = Buffer.concat(outs.map((o) => Buffer.concat([u64le(1n), u128le(o.amount), Buffer.from(o.pk), Buffer.from(o.blind)])))
  const auditBlob = Buffer.concat(outs.map((o) => Buffer.from(w.audit_memo_encrypt(1n, lo(o.amount), hi(o.amount), o.pk, o.blind, auditorPk, rnd()))))
  const shape = inputs.length === 2 ? '2x3' : '1x3'
  const t0 = Date.now()
  const r = w.transfer_prove(loadPk(`transfer_${shape}`), sh.sk, inBlob, outBlob, auditorPk, auditBlob, rnd())
  console.log(`  prove ${shape}: ${Date.now() - t0} ms`)
  const res = await api('/chains/31337/tx/transfer', {
    shape, proof: r.proof, nullifiers: r.nullifiers, freezers: r.freezers, commitments: r.commitments,
    root: r.merkle_root, owner_memos: r.owner_memos, audit_memos: r.audit_memos,
  })
  console.log('  queued as tx', res.id)
  return waitTx(res.id)
}

async function withdrawViaAggregator(sh, u, recipient, info) {
  const fee = BigInt(info.withdraw_fee)
  const mp = Buffer.from(sh.tree.proof(u.index))
  const proof = w.withdraw_prove(loadPk('withdraw'), sh.sk, u.asset, lo(u.amount), hi(u.amount), hexToBuf(recipient), lo(fee), hi(fee), hexToBuf(info.operator), u.asset, lo(u.amount), hi(u.amount), sh.pk, u.blind, mp.subarray(0, 1280), mp.readUInt32LE(1320), mp.subarray(1280, 1312), mp.readUInt32LE(1312), mp.readUInt32LE(1316), rnd())
  const res = await api('/chains/31337/tx/withdraw', {
    proof: hex(w.proof_to_evm(proof)), asset: Number(u.asset), amount: u.amount.toString(), nullifier: u.nullifier, freezer: u.freezer,
    root: sh.root(), recipient, fee: fee.toString(),
  })
  console.log('  queued as tx', res.id)
  return waitTx(res.id)
}

const bal = (a) => pub.readContract({ address: dep.token, abi: tokenAbi, functionName: 'balanceOf', args: [a] })

// ------------------------------------------------------------------- flow
const info = await api('/chains/31337/info')
console.log('aggregator:', info)
assert(info.app.toLowerCase() === dep.app.toLowerCase(), 'aggregator points at our deployment')
const transferFee = BigInt(info.transfer_fee), withdrawFee = BigInt(info.withdraw_fee)

const alice = new Shielded(new w.WasmKeypair(Buffer.from('alice-agg-' + Date.now())))
const bob = new Shielded(new w.WasmKeypair(Buffer.from('bob-agg-' + Date.now())))
const A = aliceW.account.address
await tx(aliceW, { address: dep.token, abi: tokenAbi, functionName: 'mint', args: [A, 1_000n * U] })
await tx(aliceW, { address: dep.token, abi: tokenAbi, functionName: 'approve', args: [dep.app, 1_000_000n * U] })

console.log('1. alice deposits 600 + 400 (direct)')
await deposit(aliceW, alice, 600n * U)
await deposit(aliceW, alice, 400n * U)
let live = await alice.sync()
assert(live.length === 2, 'alice has 2 notes')

console.log('2. alice -> bob 500 through the aggregator (2x3, fee', transferFee.toString(), ')')
const t1 = await transferViaAggregator(alice, live, bob.pk, 500n * U, info)
console.log('  confirmed in batch', t1.batch_id, 'tx', t1.tx_hash)
live = await alice.sync()
let bobLive = await bob.sync()
assert(live.length === 1 && live[0].amount === 500n * U - transferFee, 'alice change = 500 - fee')
assert(bobLive.length === 1 && bobLive[0].amount === 500n * U, 'bob received 500')

console.log('3. bob withdraws 500 through the aggregator (fee', withdrawFee.toString(), ')')
const bobBefore = await bal(bobAddr)
const opBefore = await bal(info.operator)
const t2 = await withdrawViaAggregator(bob, bobLive[0], bobAddr, info)
console.log('  confirmed in batch', t2.batch_id, 'tx', t2.tx_hash)
assert((await bal(bobAddr)) - bobBefore === 500n * U - withdrawFee, 'bob public +500-fee')
assert((await bal(info.operator)) - opBefore === withdrawFee, 'operator got the withdraw fee')

console.log('4. batches and aggregated proofs')
for (const id of new Set([t1.batch_id, t2.batch_id])) {
  const b = await api(`/chains/31337/batch/${id}`)
  console.log(`  batch ${id}: ${b.status}, transfers ${b.transfers}, withdraws ${b.withdraws}, tx ${b.tx_hash}`)
  for (const a of b.aggregated) {
    const r = await fetch(AGG + a.url)
    const bytes = new Uint8Array(await r.arrayBuffer())
    console.log(`    ${a.group}: ${a.proofs} proof(s) folded into ${bytes.length} bytes`)
    assert(bytes.length === a.bytes, 'proof bytes served')
  }
}

console.log('5. fee note is spendable by the aggregator key')
const aggSecret = process.env.AGGREGATOR_SECRET
if (aggSecret) {
  const aggW = new Shielded(w.WasmKeypair.from_secret(hexToBuf(aggSecret)))
  const feeNotes = await aggW.sync()
  console.log('  aggregator sees', feeNotes.length, 'fee note(s), total', feeNotes.reduce((s, u) => s + u.amount, 0n).toString())
  assert(feeNotes.some((u) => u.amount === transferFee), 'fee note found')
} else {
  console.log('  (set AGGREGATOR_SECRET to check)')
}

console.log('\nALL GOOD')
