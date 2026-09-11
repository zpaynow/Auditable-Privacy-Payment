// Chain sync: rebuild the commitment tree from NewCommitment events, find our UTXOs by
// trial-decrypting owner memos, and mark spent ones via NewNullifier events.
import { parseAbiItem, type PublicClient } from 'viem'
import { loadWasm } from './wasm'
import type { ZkKey } from './keys'
import { bytesToHex, bigintToBe32, hexToBytes, readU128le, readU64le, lo, hi, type Hex } from './encoding'
import { appAbi } from './config'

export interface Utxo {
  index: number
  commitment: Hex // bytes32 BE (as on-chain)
  commitmentLe: Uint8Array
  asset: bigint
  amount: bigint
  blind: Uint8Array
  nullifier: Hex // BE
  freezer: Hex // BE
  spent: boolean
  frozen: boolean
}

export interface SyncState {
  count: number // leaves in tree
  root: Hex
  utxos: Utxo[]
  lastBlock: bigint
}

const NEW_COMMITMENT = parseAbiItem(
  'event NewCommitment(uint32 indexed index, uint256 commitment, bytes ownerMemo, bytes auditMemo)',
)
const NEW_NULLIFIER = parseAbiItem('event NewNullifier(uint256 nullifier)')

export interface CommitmentLog {
  index: number
  commitment: bigint
  ownerMemo: Hex
  auditMemo: Hex
  blockNumber: bigint
}

const LOG_CHUNK = 5_000n

export async function fetchCommitmentLogs(
  client: PublicClient,
  app: Hex,
  fromBlock: bigint,
  toBlock: bigint,
): Promise<CommitmentLog[]> {
  const out: CommitmentLog[] = []
  for (let from = fromBlock; from <= toBlock; from += LOG_CHUNK) {
    const to = from + LOG_CHUNK - 1n > toBlock ? toBlock : from + LOG_CHUNK - 1n
    const logs = await client.getLogs({ address: app, event: NEW_COMMITMENT, fromBlock: from, toBlock: to })
    for (const l of logs) {
      out.push({
        index: Number(l.args.index!),
        commitment: l.args.commitment!,
        ownerMemo: l.args.ownerMemo!,
        auditMemo: l.args.auditMemo!,
        blockNumber: l.blockNumber!,
      })
    }
  }
  out.sort((a, b) => a.index - b.index)
  return out
}

export async function fetchNullifiers(client: PublicClient, app: Hex, fromBlock: bigint, toBlock: bigint) {
  const set = new Set<string>()
  for (let from = fromBlock; from <= toBlock; from += LOG_CHUNK) {
    const to = from + LOG_CHUNK - 1n > toBlock ? toBlock : from + LOG_CHUNK - 1n
    const logs = await client.getLogs({ address: app, event: NEW_NULLIFIER, fromBlock: from, toBlock: to })
    for (const l of logs) set.add(bytesToHex(bigintToBe32(l.args.nullifier!)))
  }
  return set
}

/**
 * Wallet-side tree. Kept for the lifetime of the page; `sync` appends new leaves.
 */
export class ShieldedWallet {
  private tree: InstanceType<Awaited<ReturnType<typeof loadWasm>>['WasmMerkleTree']> | null = null
  private w: Awaited<ReturnType<typeof loadWasm>> | null = null
  private leaves: CommitmentLog[] = []
  private nextBlock: bigint
  private client: PublicClient
  private app: Hex
  private key: ZkKey
  utxos: Utxo[] = []

  constructor(client: PublicClient, app: Hex, key: ZkKey, deployBlock: number) {
    this.client = client
    this.app = app
    this.key = key
    this.nextBlock = BigInt(deployBlock)
  }

  get count() {
    return this.leaves.length
  }

  async init() {
    this.w = await loadWasm()
    this.tree = new this.w.WasmMerkleTree(0)
  }

  /** Merkle proof blob for one of our UTXOs (tree must be committed, which sync does). */
  proofFor(index: number): Uint8Array {
    return this.tree!.proof(index)
  }

  rootEvm(): Hex {
    return bytesToHex(this.tree!.root_evm())
  }

  async sync(): Promise<SyncState> {
    if (!this.w || !this.tree) await this.init()
    const w = this.w!
    const tree = this.tree!
    const head = await this.client.getBlockNumber()
    if (head >= this.nextBlock) {
      const logs = await fetchCommitmentLogs(this.client, this.app, this.nextBlock, head)
      for (const l of logs) {
        if (l.index !== this.leaves.length) {
          throw new Error(`commitment index gap: expected ${this.leaves.length}, got ${l.index}`)
        }
        const commLe = w.fr_from_evm(bigintToBe32(l.commitment))
        tree.add_leaf(commLe)
        this.leaves.push(l)
        // is it ours?
        try {
          const dec = w.owner_memo_decrypt(this.key.secret, commLe, hexToBytes(l.ownerMemo))
          const asset = readU64le(dec, 0)
          const amount = readU128le(dec, 8)
          const blind = dec.slice(24, 56)
          const nullifier = bytesToHex(w.fr_to_evm(w.compute_nullifier(this.key.secret, asset, lo(amount), hi(amount), blind)))
          const freezer = bytesToHex(w.fr_to_evm(w.freezer_of(commLe, this.key.pk.slice(0, 32))))
          this.utxos.push({
            index: l.index,
            commitment: bytesToHex(bigintToBe32(l.commitment)),
            commitmentLe: commLe,
            asset,
            amount,
            blind,
            nullifier,
            freezer,
            spent: false,
            frozen: false,
          })
        } catch {
          /* not our memo */
        }
      }
      if (logs.length) tree.commit()
      this.nextBlock = head + 1n
    }

    // spent + frozen status for our unspent UTXOs
    const nulls = await fetchNullifiers(this.client, this.app, BigInt(0), head)
    for (const u of this.utxos) {
      u.spent = nulls.has(u.nullifier)
    }
    const live = this.utxos.filter((u) => !u.spent)
    if (live.length) {
      const frozen = await Promise.all(
        live.map((u) =>
          this.client.readContract({ address: this.app, abi: appAbi, functionName: 'frozen', args: [BigInt(u.freezer)] }),
        ),
      )
      live.forEach((u, i) => (u.frozen = Boolean(frozen[i])))
    }

    return {
      count: this.leaves.length,
      root: this.leaves.length ? this.rootEvm() : ('0x' + '0'.repeat(64)) as Hex,
      utxos: [...this.utxos],
      lastBlock: head,
    }
  }
}

/** Auditor view: decrypt every audit memo with the auditor secret. */
export interface AuditRow {
  index: number
  commitment: Hex
  asset: bigint
  amount: bigint
  ownerX: Hex // LE hex as stored in wasm pk
  ownerAddress: Hex // 64-byte payment address
  freezer: Hex // BE
  blockNumber: bigint
}

export async function auditScan(client: PublicClient, app: Hex, deployBlock: number, auditorSecret: Uint8Array) {
  const w = await loadWasm()
  const head = await client.getBlockNumber()
  const logs = await fetchCommitmentLogs(client, app, BigInt(deployBlock), head)
  const rows: AuditRow[] = []
  for (const l of logs) {
    try {
      const dec = w.audit_memo_decrypt(auditorSecret, hexToBytes(l.auditMemo))
      const asset = readU64le(dec, 0)
      const amount = readU128le(dec, 8)
      const ownerX = dec.slice(24, 56)
      const ownerY = dec.slice(56, 88)
      const commLe = w.fr_from_evm(bigintToBe32(l.commitment))
      const freezer = bytesToHex(w.fr_to_evm(w.freezer_of(commLe, ownerX)))
      const pk = new Uint8Array(64)
      pk.set(ownerX, 0)
      pk.set(ownerY, 32)
      rows.push({
        index: l.index,
        commitment: bytesToHex(bigintToBe32(l.commitment)),
        asset,
        amount,
        ownerX: bytesToHex(ownerX),
        ownerAddress: bytesToHex(pk),
        freezer,
        blockNumber: l.blockNumber,
      })
    } catch {
      rows.push({
        index: l.index,
        commitment: bytesToHex(bigintToBe32(l.commitment)),
        asset: 0n,
        amount: -1n,
        ownerX: '0x',
        ownerAddress: '0x',
        freezer: '0x',
        blockNumber: l.blockNumber,
      })
    }
  }
  return rows
}
