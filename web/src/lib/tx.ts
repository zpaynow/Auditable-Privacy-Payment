// Build and send the three shielded operations. Each returns after the tx is mined.
import type { PublicClient, WalletClient } from 'viem'
import { loadWasm } from './wasm'
import { prove } from './prover'
import type { ZkKey } from './keys'
import type { NoteSource, Utxo } from './sync'
import { appAbi, tokenAbi, ASSET_ID, type Deployment } from './config'
import { submitTransfer, submitWithdraw, waitForTx, type AggregatorInfo } from './aggregator'
import {
  addressToBytes,
  bigintToBe32,
  bytesToHex,
  concat,
  hexToBytes,
  randomBytes,
  u128le,
  u64le,
  be32ToBigint,
  type Hex,
} from './encoding'

export type Progress = (step: string) => void

function proofWords(proofEvm: Uint8Array): readonly [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint] {
  const w: bigint[] = []
  for (let i = 0; i < 8; i++) w.push(be32ToBigint(proofEvm.slice(i * 32, i * 32 + 32)))
  return w as unknown as readonly [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint]
}

function auditorPk(d: Deployment): Uint8Array {
  // deployment stores EVM bytes32 (BE) coordinates; wasm wants x||y LE
  return concat(be32ToLe(BigInt(d.auditorX)), be32ToLe(BigInt(d.auditorY)))
}

function be32ToLe(n: bigint): Uint8Array {
  return bigintToBe32(n).reverse()
}

interface Ctx {
  publicClient: PublicClient
  walletClient: WalletClient
  deployment: Deployment
  key: ZkKey
  account: Hex
}

async function send(ctx: Ctx, request: Parameters<WalletClient['writeContract']>[0], onProgress: Progress) {
  onProgress('Confirm in wallet…')
  const hash = await ctx.walletClient.writeContract(request)
  onProgress('Waiting for confirmation…')
  const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error('transaction reverted')
  return hash
}

// ------------------------------------------------------------------ deposit
export async function deposit(ctx: Ctx, amount: bigint, onProgress: Progress): Promise<Hex> {
  const w = await loadWasm()
  const { deployment: d, key } = ctx
  const asset = ASSET_ID
  const lo = amount & ((1n << 64n) - 1n)
  const hi = amount >> 64n

  onProgress('Building note…')
  const blind = w.generate_random_blind(randomBytes(32))
  const commitmentLe = w.compute_commitment(asset, lo, hi, key.pk, blind)
  const commitment = be32ToBigint(w.fr_to_evm(commitmentLe))
  const ownerMemo = w.owner_memo_encrypt(asset, lo, hi, key.pk, blind, randomBytes(32))
  const auditBlob = w.audit_memo_encrypt(asset, lo, hi, key.pk, blind, auditorPk(d), randomBytes(32))
  const auditMemo = auditBlob.slice(0, 160)
  const auditShare = auditBlob.slice(160, 192)

  // allowance
  const allowance = (await ctx.publicClient.readContract({
    address: d.token,
    abi: tokenAbi,
    functionName: 'allowance',
    args: [ctx.account, d.app],
  })) as bigint
  if (allowance < amount) {
    await send(
      ctx,
      {
        address: d.token,
        abi: tokenAbi,
        functionName: 'approve',
        args: [d.app, amount],
        account: ctx.account,
        chain: ctx.walletClient.chain,
      },
      (s) => onProgress(`Approve token: ${s}`),
    )
  }

  onProgress('Generating proof (this can take a while)…')
  const { result, ms } = await prove<{ proofEvm: Uint8Array }>({
    kind: 'deposit',
    asset,
    amount,
    ownerPk: key.pk,
    blind,
    auditorPk: auditorPk(d),
    auditMemo,
    auditShare,
  })
  onProgress(`Proof ready in ${(ms / 1000).toFixed(1)} s`)

  return send(
    ctx,
    {
      address: d.app,
      abi: appAbi,
      functionName: 'deposit',
      args: [asset, amount, commitment, bytesToHex(ownerMemo), bytesToHex(auditMemo), proofWords(result.proofEvm)],
      account: ctx.account,
      chain: ctx.walletClient.chain,
    },
    onProgress,
  )
}

// ----------------------------------------------------------------- transfer
/** Pick inputs: two largest if we have ≥2 unspent, else one. Must cover `amount`. */
export function selectInputs(utxos: Utxo[], amount: bigint): Utxo[] {
  const live = utxos.filter((u) => !u.spent && !u.frozen && u.asset === ASSET_ID).sort((a, b) => (a.amount > b.amount ? -1 : 1))
  if (live.length >= 2) {
    // prefer a pair that covers; try largest+each
    for (let i = 1; i < live.length; i++) {
      if (live[0].amount + live[i].amount >= amount) return [live[0], live[i]]
    }
  }
  if (live.length >= 1 && live[0].amount >= amount) return [live[0]]
  const total = live.reduce((s, u) => s + u.amount, 0n)
  throw new Error(`insufficient shielded balance in at most two notes (have ${total}, need ${amount}). Consolidate first.`)
}

export interface TransferResult {
  proof: Hex
  publics: Hex[]
  nullifiers: Hex[]
  freezers: Hex[]
  commitments: Hex[]
  merkle_root: Hex
  owner_memos: Hex[]
  audit_memos: Hex[]
}

export async function transfer(
  ctx: Ctx,
  wallet: NoteSource,
  to: Uint8Array,
  amount: bigint,
  onProgress: Progress,
): Promise<Hex> {
  const w = await loadWasm()
  const { deployment: d, key } = ctx
  const asset = ASSET_ID
  const inputs = selectInputs(wallet.utxos, amount)
  const total = inputs.reduce((s, u) => s + u.amount, 0n)
  const change = total - amount

  onProgress('Building notes…')
  const { proofs: mps } = await wallet.proofsFor(inputs.map((u) => u.index))
  const inBlob = concat(...inputs.map((u, i) => concat(u64le(u.asset), u128le(u.amount), u.blind, mps[i])))
  const outs = [
    { amount, pk: to, blind: w.generate_random_blind(randomBytes(32)) },
    { amount: change, pk: key.pk, blind: w.generate_random_blind(randomBytes(32)) },
  ]
  const outBlob = concat(...outs.map((o) => concat(u64le(asset), u128le(o.amount), o.pk, o.blind)))
  const apk = auditorPk(d)
  const auditBlob = concat(
    ...outs.map((o) => {
      const lo = o.amount & ((1n << 64n) - 1n)
      const hi = o.amount >> 64n
      return w.audit_memo_encrypt(asset, lo, hi, o.pk, o.blind, apk, randomBytes(32))
    }),
  )

  onProgress(`Generating proof (${inputs.length} in / 2 out, this can take a while)…`)
  const { result: r, ms } = await prove<TransferResult>({
    kind: 'transfer',
    shape: inputs.length === 2 ? '2x2' : '1x2',
    secret: key.secret,
    inputs: inBlob,
    outputs: outBlob,
    auditorPk: apk,
    auditMemos: auditBlob,
  })
  onProgress(`Proof ready in ${(ms / 1000).toFixed(1)} s`)

  const proof = proofWords(hexToBytes(r.proof))
  const commitments = [BigInt(r.commitments[0]), BigInt(r.commitments[1])] as const
  const ownerMemos = [r.owner_memos[0], r.owner_memos[1]] as const
  const auditMemos = [r.audit_memos[0], r.audit_memos[1]] as const
  const root = BigInt(r.merkle_root)

  if (inputs.length === 2) {
    return send(
      ctx,
      {
        address: d.app,
        abi: appAbi,
        functionName: 'transfer',
        args: [
          [BigInt(r.nullifiers[0]), BigInt(r.nullifiers[1])],
          [BigInt(r.freezers[0]), BigInt(r.freezers[1])],
          commitments,
          root,
          ownerMemos,
          auditMemos,
          proof,
        ],
        account: ctx.account,
        chain: ctx.walletClient.chain,
      },
      onProgress,
    )
  }
  return send(
    ctx,
    {
      address: d.app,
      abi: appAbi,
      functionName: 'transfer1',
      args: [BigInt(r.nullifiers[0]), BigInt(r.freezers[0]), commitments, root, ownerMemos, auditMemos, proof],
      account: ctx.account,
      chain: ctx.walletClient.chain,
    },
    onProgress,
  )
}

// ----------------------------------------------------------------- withdraw
export async function withdraw(
  ctx: Ctx,
  wallet: NoteSource,
  utxo: Utxo,
  recipient: Hex,
  onProgress: Progress,
): Promise<Hex> {
  const { deployment: d, key } = ctx
  const fee = 0n
  const { proofs: [mp], root } = await wallet.proofsFor([utxo.index])
  onProgress('Generating proof (this can take a while)…')
  const { result, ms } = await prove<{ proofEvm: Uint8Array }>({
    kind: 'withdraw',
    secret: key.secret,
    asset: utxo.asset,
    amount: utxo.amount,
    recipient: addressToBytes(recipient),
    fee,
    inputBlind: utxo.blind,
    ownerPk: key.pk,
    merkleProof: mp,
  })
  onProgress(`Proof ready in ${(ms / 1000).toFixed(1)} s`)
  return send(
    ctx,
    {
      address: d.app,
      abi: appAbi,
      functionName: 'withdraw',
      args: [
        utxo.asset,
        utxo.amount,
        BigInt(utxo.nullifier),
        BigInt(utxo.freezer),
        BigInt(root),
        recipient,
        fee,
        proofWords(result.proofEvm),
      ],
      account: ctx.account,
      chain: ctx.walletClient.chain,
    },
    onProgress,
  )
}

// ------------------------------------------------------------------ auditor
export async function setFrozen(ctx: Ctx, freezer: Hex, frozen: boolean, onProgress: Progress) {
  return send(
    ctx,
    {
      address: ctx.deployment.app,
      abi: appAbi,
      functionName: 'setFrozen',
      args: [BigInt(freezer), frozen],
      account: ctx.account,
      chain: ctx.walletClient.chain,
    },
    onProgress,
  )
}

export async function mintTestToken(ctx: Ctx, amount: bigint, onProgress: Progress) {
  return send(
    ctx,
    {
      address: ctx.deployment.token,
      abi: tokenAbi,
      functionName: 'mint',
      args: [ctx.account, amount],
      account: ctx.account,
      chain: ctx.walletClient.chain,
    },
    onProgress,
  )
}


// ------------------------------------------------------ via the aggregator
/// Shielded transfer settled by the aggregator: 3 outputs [to, change, fee -> aggregator key].
/// No wallet transaction; the fee is paid inside the pool.
export async function transferViaAggregator(
  ctx: Ctx,
  wallet: NoteSource,
  to: Uint8Array,
  amount: bigint,
  info: AggregatorInfo,
  onProgress: Progress,
): Promise<Hex> {
  const w = await loadWasm()
  const { deployment: d, key } = ctx
  const asset = ASSET_ID
  const fee = BigInt(info.transfer_fee)
  const inputs = selectInputs(wallet.utxos, amount + fee)
  const total = inputs.reduce((s, u) => s + u.amount, 0n)
  const change = total - amount - fee

  onProgress('Building notes (incl. fee note)…')
  const { proofs: mps } = await wallet.proofsFor(inputs.map((u) => u.index))
  const inBlob = concat(...inputs.map((u, i) => concat(u64le(u.asset), u128le(u.amount), u.blind, mps[i])))
  const outs = [
    { amount, pk: to, blind: w.generate_random_blind(randomBytes(32)) },
    { amount: change, pk: key.pk, blind: w.generate_random_blind(randomBytes(32)) },
    { amount: fee, pk: hexToBytes(info.aggregator_pk), blind: w.generate_random_blind(randomBytes(32)) },
  ]
  const outBlob = concat(...outs.map((o) => concat(u64le(asset), u128le(o.amount), o.pk, o.blind)))
  const apk = auditorPk(d)
  const auditBlob = concat(
    ...outs.map((o) => w.audit_memo_encrypt(asset, o.amount & ((1n << 64n) - 1n), o.amount >> 64n, o.pk, o.blind, apk, randomBytes(32))),
  )
  const shape = inputs.length === 2 ? '2x3' : '1x3'
  onProgress(`Generating proof (${shape}, this can take a while)…`)
  const { result: r, ms } = await prove<TransferResult>({
    kind: 'transfer',
    shape,
    secret: key.secret,
    inputs: inBlob,
    outputs: outBlob,
    auditorPk: apk,
    auditMemos: auditBlob,
  })
  onProgress(`Proof ready in ${(ms / 1000).toFixed(1)} s, submitting to the aggregator…`)
  const { id } = await submitTransfer({
    shape,
    proof: r.proof,
    nullifiers: r.nullifiers,
    freezers: r.freezers,
    commitments: r.commitments,
    root: r.merkle_root,
    owner_memos: r.owner_memos,
    audit_memos: r.audit_memos,
  })
  const status = await waitForTx(id, onProgress)
  return (status.tx_hash ?? '0x') as Hex
}

/// Withdraw settled by the aggregator: the fee field pays the operator, no wallet transaction.
export async function withdrawViaAggregator(
  ctx: Ctx,
  wallet: NoteSource,
  utxo: Utxo,
  recipient: Hex,
  info: AggregatorInfo,
  onProgress: Progress,
): Promise<Hex> {
  const { key } = ctx
  const fee = BigInt(info.withdraw_fee)
  if (fee > utxo.amount) throw new Error('note is smaller than the withdraw fee')
  const { proofs: [mp], root } = await wallet.proofsFor([utxo.index])
  onProgress('Generating proof (this can take a while)…')
  const { result, ms } = await prove<{ proofEvm: Uint8Array }>({
    kind: 'withdraw',
    secret: key.secret,
    asset: utxo.asset,
    amount: utxo.amount,
    recipient: addressToBytes(recipient),
    fee,
    inputBlind: utxo.blind,
    ownerPk: key.pk,
    merkleProof: mp,
  })
  onProgress(`Proof ready in ${(ms / 1000).toFixed(1)} s, submitting to the aggregator…`)
  const { id } = await submitWithdraw({
    proof: bytesToHex(result.proofEvm),
    asset: Number(utxo.asset),
    amount: utxo.amount.toString(),
    nullifier: utxo.nullifier,
    freezer: utxo.freezer,
    root,
    recipient,
    fee: fee.toString(),
  })
  const status = await waitForTx(id, onProgress)
  return (status.tx_hash ?? '0x') as Hex
}
