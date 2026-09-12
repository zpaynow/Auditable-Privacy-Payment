// Chain sync: rebuild the commitment tree from NewCommitment events, find our UTXOs by
// trial-decrypting owner memos, and mark spent ones via NewNullifier events.
import { parseAbiItem, type PublicClient } from 'viem'
import { loadWasm } from './wasm'
import type { ZkKey } from './keys'
import { bytesToHex, bigintToBe32, hexToBytes, readU128le, readU64le, lo, hi, type Hex } from './encoding'
import { appAbi } from './config'
import { checkNullifiers, getNotes, getProof, getStatus } from './auditorClient'

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
  /** where the notes came from */
  mode: 'chain' | 'auditor'
}

/** What the transaction builders need from a wallet, regardless of how it syncs. */
export interface NoteSource {
  readonly utxos: Utxo[]
  sync(): Promise<SyncState>
  /** Merkle proofs for the given leaves, all against one root (EVM bytes32). */
  proofsFor(indices: number[]): Promise<{ proofs: Uint8Array[]; root: Hex }>
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
export class ShieldedWallet implements NoteSource {
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

  async proofsFor(indices: number[]): Promise<{ proofs: Uint8Array[]; root: Hex }> {
    return { proofs: indices.map((i) => this.tree!.proof(i)), root: this.rootEvm() }
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
      mode: 'chain',
    }
  }
}

/**
 * Wallet backed by the auditor service: no chain scanning and no local tree. The service
 * knows which notes belong to our key (it opens every audit memo); we still decrypt the owner
 * memos locally to learn the blinds, so only we can spend.
 */
export class RemoteWallet implements NoteSource {
  private w: Awaited<ReturnType<typeof loadWasm>> | null = null
  private key: ZkKey
  private chainId: number
  private app: Hex
  utxos: Utxo[] = []

  constructor(key: ZkKey, chainId: number, app: Hex) {
    this.key = key
    this.chainId = chainId
    this.app = app
  }

  async sync(): Promise<SyncState> {
    if (!this.w) this.w = await loadWasm()
    const w = this.w
    const [status, notes] = await Promise.all([getStatus(this.chainId), getNotes(this.key, this.chainId, this.app)])
    const known = new Map(this.utxos.map((u) => [u.index, u]))
    for (const n of notes) {
      if (known.has(n.index)) {
        known.get(n.index)!.frozen = n.frozen
        continue
      }
      const commLe = w.fr_from_evm(hexToBytes(n.commitment))
      try {
        const dec = w.owner_memo_decrypt(this.key.secret, commLe, hexToBytes(n.owner_memo))
        const asset = readU64le(dec, 0)
        const amount = readU128le(dec, 8)
        const blind = dec.slice(24, 56)
        const nullifier = bytesToHex(w.fr_to_evm(w.compute_nullifier(this.key.secret, asset, lo(amount), hi(amount), blind)))
        this.utxos.push({
          index: n.index,
          commitment: n.commitment,
          commitmentLe: commLe,
          asset,
          amount,
          blind,
          nullifier,
          freezer: n.freezer,
          spent: false,
          frozen: n.frozen,
        })
      } catch {
        /* the service attributed a note to us that our key cannot open: ignore */
      }
    }
    this.utxos.sort((a, b) => a.index - b.index)
    const live = this.utxos.filter((u) => !u.spent)
    if (live.length) {
      const spent = await checkNullifiers(this.chainId, live.map((u) => u.nullifier))
      live.forEach((u, i) => (u.spent = spent[i]))
    }
    return {
      count: status.notes,
      root: status.root,
      utxos: [...this.utxos],
      lastBlock: BigInt(status.indexed_block ?? 0),
      mode: 'auditor',
    }
  }

  async proofsFor(indices: number[]): Promise<{ proofs: Uint8Array[]; root: Hex }> {
    // all proofs must open to the same root; retry once if the tree moved between requests
    for (let attempt = 0; attempt < 3; attempt++) {
      const ps = []
      for (const i of indices) ps.push(await getProof(this.key, this.chainId, this.app, i))
      const root = ps[0].root
      if (ps.every((p) => p.root === root)) return { proofs: ps.map((p) => hexToBytes(p.proof)), root }
    }
    throw new Error('auditor service tree changed while fetching proofs; try again')
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

/**
 * Decrypt audit memos with the auditor secret.
 * `fromBlock` limits the scan (e.g. the block when the auditor tab was opened);
 * `lastN` keeps only the newest N notes of that range.
 */
export async function auditScan(
  client: PublicClient,
  app: Hex,
  fromBlock: number | bigint,
  auditorSecret: Uint8Array,
  lastN?: number,
) {
  const w = await loadWasm()
  const head = await client.getBlockNumber()
  let logs = await fetchCommitmentLogs(client, app, BigInt(fromBlock), head)
  if (lastN !== undefined && logs.length > lastN) logs = logs.slice(logs.length - lastN)
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
