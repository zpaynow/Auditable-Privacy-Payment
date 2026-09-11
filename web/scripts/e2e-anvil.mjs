// End-to-end test against a local anvil deployment, using the same wasm + contracts as the web app.
//
//   anvil &  (in another terminal)
//   cd solidity && AUDITOR_X=... AUDITOR_Y=... forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 \
//        --unlocked --sender 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --broadcast
//   cd web && ./scripts/sync.sh && AUDITOR_SECRET=0x... node scripts/e2e-anvil.mjs
//
// Flow: alice deposits 600 + 400 -> transfers 700 to bob (2-in) -> bob withdraws 700 ->
//       auditor freezes alice's change -> alice's 1-in transfer is rejected -> unfreeze -> succeeds.
import fs from 'node:fs'
import crypto from 'node:crypto'
import { createRequire } from 'node:module'
import { createPublicClient, createWalletClient, http, parseAbiItem, defineChain } from 'viem'
import { mnemonicToAccount } from 'viem/accounts'

const require = createRequire(import.meta.url)
const w = require('../../wasm/pkg-node/wasm.js')
const ROOT = new URL('../..', import.meta.url).pathname
const RPC = process.env.RPC ?? 'http://127.0.0.1:8545'
const dep = JSON.parse(fs.readFileSync(`${ROOT}web/src/deployments/31337.json`, 'utf8'))
const appAbi = JSON.parse(fs.readFileSync(`${ROOT}web/src/abi/APP.json`, 'utf8'))
const tokenAbi = JSON.parse(fs.readFileSync(`${ROOT}web/src/abi/TestToken.json`, 'utf8'))
const AUDITOR_SECRET = process.env.AUDITOR_SECRET
if (!AUDITOR_SECRET) throw new Error('set AUDITOR_SECRET (from app-tools keygen, matching the deployment)')

const chain = defineChain({ id: 31337, name: 'anvil', nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [RPC] } } })
const pub = createPublicClient({ chain, transport: http(RPC) })
// anvil's default mnemonic, accounts #0 (deployer / auditor admin) and #1
const MNEMONIC = 'test test test test test test test test test test test junk'
const wallets = [0, 1].map((i) => createWalletClient({ account: mnemonicToAccount(MNEMONIC, { addressIndex: i }), chain, transport: http(RPC) }))

// ---------------------------------------------------------------- helpers
const U = 10n ** 6n // tUSD has 6 decimals; amounts below are in whole tUSD
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
const t = (label, f) => async (...a) => { const s = Date.now(); const r = await f(...a); console.log(`  ${label}: ${Date.now() - s} ms`); return r }

async function tx(wallet, req) {
  const hash = await wallet.writeContract({ ...req, account: wallet.account, chain })
  const r = await pub.waitForTransactionReceipt({ hash })
  if (r.status !== 'success') throw new Error('reverted')
  return r
}

// A shielded wallet that mirrors web/src/lib/sync.ts
class Shielded {
  constructor(kp) { this.kp = kp; this.sk = kp.secret_key(); this.pk = kp.public_key(); this.tree = new w.WasmMerkleTree(0); this.n = 0; this.utxos = [] }
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
  root() { return BigInt(hex(this.tree.root_evm())) }
}

async function deposit(wallet, sh, amount) {
  const blind = w.generate_random_blind(rnd())
  const commLe = w.compute_commitment(1n, lo(amount), hi(amount), sh.pk, blind)
  const ownerMemo = w.owner_memo_encrypt(1n, lo(amount), hi(amount), sh.pk, blind, rnd())
  const ab = w.audit_memo_encrypt(1n, lo(amount), hi(amount), sh.pk, blind, auditorPk, rnd())
  const proof = await t('deposit_prove', async () => w.deposit_prove(loadPk('deposit'), 1n, lo(amount), hi(amount), sh.pk, blind, auditorPk, ab.slice(0, 160), ab.slice(160), rnd()))()
  return tx(wallet, { address: dep.app, abi: appAbi, functionName: 'deposit', args: [1n, amount, BigInt(hex(w.fr_to_evm(commLe))), hex(ownerMemo), hex(ab.slice(0, 160)), words(w.proof_to_evm(proof))] })
}

async function transfer(wallet, sh, inputs, toPk, amount) {
  const total = inputs.reduce((s, u) => s + u.amount, 0n)
  const inBlob = Buffer.concat(inputs.map((u) => Buffer.concat([u64le(u.asset), u128le(u.amount), Buffer.from(u.blind), Buffer.from(sh.tree.proof(u.index))])))
  const outs = [{ amount, pk: toPk }, { amount: total - amount, pk: sh.pk }].map((o) => ({ ...o, blind: w.generate_random_blind(rnd()) }))
  const outBlob = Buffer.concat(outs.map((o) => Buffer.concat([u64le(1n), u128le(o.amount), Buffer.from(o.pk), Buffer.from(o.blind)])))
  const auditBlob = Buffer.concat(outs.map((o) => Buffer.from(w.audit_memo_encrypt(1n, lo(o.amount), hi(o.amount), o.pk, o.blind, auditorPk, rnd()))))
  const shape = inputs.length === 2 ? 'transfer_2x2' : 'transfer_1x2'
  const r = await t(`${shape} prove`, async () => w.transfer_prove(loadPk(shape), sh.sk, inBlob, outBlob, auditorPk, auditBlob, rnd()))()
  const proof = words(hexToBuf(r.proof))
  const comms = r.commitments.map(BigInt)
  if (inputs.length === 2) {
    return tx(wallet, { address: dep.app, abi: appAbi, functionName: 'transfer', args: [r.nullifiers.map(BigInt), r.freezers.map(BigInt), comms, BigInt(r.merkle_root), r.owner_memos, r.audit_memos, proof] })
  }
  return tx(wallet, { address: dep.app, abi: appAbi, functionName: 'transfer1', args: [BigInt(r.nullifiers[0]), BigInt(r.freezers[0]), comms, BigInt(r.merkle_root), r.owner_memos, r.audit_memos, proof] })
}

async function withdraw(wallet, sh, u, recipient) {
  const mp = Buffer.from(sh.tree.proof(u.index))
  const proof = await t('withdraw_prove', async () => w.withdraw_prove(loadPk('withdraw'), sh.sk, u.asset, lo(u.amount), hi(u.amount), hexToBuf(recipient), 0n, 0n, u.asset, lo(u.amount), hi(u.amount), sh.pk, u.blind, mp.subarray(0, 1280), mp.readUInt32LE(1320), mp.subarray(1280, 1312), mp.readUInt32LE(1312), mp.readUInt32LE(1316), rnd()))()
  return tx(wallet, { address: dep.app, abi: appAbi, functionName: 'withdraw', args: [u.asset, u.amount, BigInt(u.nullifier), BigInt(u.freezer), sh.root(), recipient, 0n, words(w.proof_to_evm(proof))] })
}

const bal = (a) => pub.readContract({ address: dep.token, abi: tokenAbi, functionName: 'balanceOf', args: [a] })
const assert = (c, m) => { if (!c) throw new Error('assertion failed: ' + m) }

// ------------------------------------------------------------------- flow
const [aliceW, bobW] = wallets
const alice = new Shielded(new w.WasmKeypair(Buffer.from('alice-e2e-' + Date.now())))
const bob = new Shielded(new w.WasmKeypair(Buffer.from('bob-e2e-' + Date.now())))
const A = aliceW.account.address, B = bobW.account.address

console.log('APP', dep.app, 'token', dep.token)
const bobBefore = await bal(B)
await tx(aliceW, { address: dep.token, abi: tokenAbi, functionName: 'mint', args: [A, 1_000n * U] })
await tx(aliceW, { address: dep.token, abi: tokenAbi, functionName: 'approve', args: [dep.app, 1_000_000n * U] })

console.log('1. alice deposits 600 and 400')
let r = await deposit(aliceW, alice, 600n * U); console.log('  gas', r.gasUsed)
r = await deposit(aliceW, alice, 400n * U); console.log('  gas', r.gasUsed)
let live = await alice.sync()
assert(live.length === 2 && live.reduce((s, u) => s + u.amount, 0n) === 1000n * U, 'alice sees 2 notes = 1000')
assert(alice.root() === (await pub.readContract({ address: dep.app, abi: appAbi, functionName: 'getLastRoot' })), 'local root == chain root')

console.log('2. alice transfers 700 to bob (2-in / 2-out)')
r = await transfer(aliceW, alice, live, bob.pk, 700n * U); console.log('  gas', r.gasUsed)
live = await alice.sync()
assert(live.length === 1 && live[0].amount === 300n * U, 'alice has 300 change')
let bobLive = await bob.sync()
assert(bobLive.length === 1 && bobLive[0].amount === 700n * U, 'bob received 700')

console.log('3. bob withdraws 700 to his address')
r = await withdraw(bobW, bob, bobLive[0], B); console.log('  gas', r.gasUsed)
assert((await bal(B)) - bobBefore === 700n * U, 'bob public balance +700')

console.log('4. auditor decrypts the pool and freezes alice\'s change note')
const head = await pub.getBlockNumber()
const logs = await pub.getLogs({ address: dep.app, event: parseAbiItem('event NewCommitment(uint32 indexed index, uint256 commitment, bytes ownerMemo, bytes auditMemo)'), fromBlock: BigInt(dep.deployBlock), toBlock: head })
const rows = logs.map((l) => { const d = Buffer.from(w.audit_memo_decrypt(hexToBuf(AUDITOR_SECRET), hexToBuf(l.args.auditMemo))); return { index: Number(l.args.index), amount: d.readBigUInt64LE(8) | (d.readBigUInt64LE(16) << 64n), ownerX: d.subarray(24, 56), commLe: w.fr_from_evm(be32(l.args.commitment)) } })
const change = rows.find((x) => x.index === live[0].index)
assert(change && change.amount === 300n * U && Buffer.compare(change.ownerX, Buffer.from(alice.pk.slice(0, 32))) === 0, 'auditor opened alice change note: 300, owner alice')
const freezer = BigInt(hex(w.fr_to_evm(w.freezer_of(change.commLe, change.ownerX))))
assert(freezer === BigInt(live[0].freezer), 'auditor freezer == owner freezer')
await tx(aliceW /* auditorAdmin = deployer */, { address: dep.app, abi: appAbi, functionName: 'setFrozen', args: [freezer, true] })

console.log('5. alice tries to spend the frozen note (1-in / 2-out): must revert')
let reverted = false
try { await transfer(aliceW, alice, live, bob.pk, 100n * U) } catch (e) { reverted = true; console.log('  reverted as expected:', String(e.message).split('\n').find((l) => l.includes('Frozen')) ?? 'Frozen()') }
assert(reverted, 'frozen spend rejected')

console.log('6. unfreeze, then alice sends 100 to bob with the 1-in shape')
await tx(aliceW, { address: dep.app, abi: appAbi, functionName: 'setFrozen', args: [freezer, false] })
r = await transfer(aliceW, alice, live, bob.pk, 100n * U); console.log('  gas', r.gasUsed)
live = await alice.sync(); bobLive = await bob.sync()
assert(live.length === 1 && live[0].amount === 200n * U, 'alice change 200')
assert(bobLive.length === 1 && bobLive[0].amount === 100n * U, 'bob has 100 shielded')
console.log('\nALL GOOD: pool holds', (await bal(dep.app)) / U, 'tUSD; alice shielded 200, bob shielded 100, bob public +700')
