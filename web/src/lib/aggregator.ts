// Client for the aggregator service (aggregator/): quotes, submission, status polling.
import type { Hex } from './encoding'

export const AGGREGATOR_URL: string = (import.meta.env.VITE_AGGREGATOR_URL as string | undefined) ?? 'http://127.0.0.1:8787'

export interface AggregatorInfo {
  chain_id: number
  app: string
  operator: string
  /** 64-byte x||y LE hex: owner of fee notes */
  aggregator_pk: Hex
  fee_asset: number
  transfer_fee: string
  withdraw_fee: string
  batch_max: number
  batch_interval_secs: number
  pending: number
}

export interface TxStatus {
  id: number
  kind: string
  status: 'pending' | 'submitted' | 'confirmed' | 'failed'
  batch_id: number | null
  tx_hash: string | null
  error: string | null
}

async function call<T>(path: string, body?: unknown): Promise<T> {
  const r = await fetch(AGGREGATOR_URL + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined)
  const text = await r.text()
  let json: unknown = null
  try {
    json = JSON.parse(text)
  } catch {
    /* not json */
  }
  if (!r.ok) {
    const err = (json as { error?: string } | null)?.error ?? text ?? r.statusText
    throw new Error(`aggregator: ${err}`)
  }
  return json as T
}

export function getInfo(chainId: number): Promise<AggregatorInfo> {
  return call<AggregatorInfo>(`/chains/${chainId}/info`)
}

export interface TransferSubmit {
  shape: '2x3' | '1x3'
  proof: Hex
  nullifiers: Hex[]
  freezers: Hex[]
  commitments: Hex[]
  root: Hex
  owner_memos: Hex[]
  audit_memos: Hex[]
}

export interface WithdrawSubmit {
  proof: Hex
  asset: number
  amount: string
  nullifier: Hex
  freezer: Hex
  root: Hex
  recipient: Hex
  fee: string
}

export function submitTransfer(chainId: number, t: TransferSubmit): Promise<{ id: number }> {
  return call(`/chains/${chainId}/tx/transfer`, t)
}

export function submitWithdraw(chainId: number, w: WithdrawSubmit): Promise<{ id: number }> {
  return call(`/chains/${chainId}/tx/withdraw`, w)
}

export function getTx(chainId: number, id: number): Promise<TxStatus> {
  return call(`/chains/${chainId}/tx/${id}`)
}

/** Poll until the aggregator has settled the tx on-chain. */
export async function waitForTx(chainId: number, id: number, onProgress: (s: string) => void, timeoutMs = 10 * 60_000): Promise<TxStatus> {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const s = await getTx(chainId, id)
    if (s.status === 'confirmed') return s
    if (s.status === 'failed') throw new Error(`aggregator rejected the transaction: ${s.error ?? 'unknown error'}`)
    onProgress(s.status === 'submitted' ? `Batch ${s.batch_id} sent, waiting for confirmation…` : `Queued at the aggregator (#${id}), waiting for the next batch…`)
    await new Promise((r) => setTimeout(r, 2000))
  }
  throw new Error('timed out waiting for the aggregator')
}
