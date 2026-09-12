// Client for the auditor service (auditor/): fetch our notes and Merkle proofs instead of
// scanning the chain. Requests are authenticated with a Schnorr signature by the payment key.
import { loadWasm } from './wasm'
import type { ZkKey } from './keys'
import { bytesToHex, type Hex } from './encoding'

export const AUDITOR_URL: string = (import.meta.env.VITE_AUDITOR_URL as string | undefined) ?? 'http://127.0.0.1:8788'

export interface AuditorStatus {
  chain_id: number
  app: string
  indexed_block: number | null
  notes: number
  nullifiers: number
  root: Hex
  tree_version: number
}

export interface RemoteNote {
  index: number
  commitment: Hex
  owner_memo: Hex
  audit_memo: Hex
  owner: Hex
  asset: number
  amount: string
  freezer: Hex
  frozen: boolean
  block: number
  tx_hash: string
}

export interface RemoteProof {
  index: number
  proof: Hex
  root: Hex
  version: number
  count: number
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(AUDITOR_URL + path, init)
  const text = await r.text()
  let json: unknown = null
  try {
    json = JSON.parse(text)
  } catch {
    /* not json */
  }
  if (!r.ok) throw new Error(`auditor service: ${(json as { error?: string } | null)?.error ?? text ?? r.statusText}`)
  return json as T
}

export function getStatus(chainId: number): Promise<AuditorStatus> {
  return request(`/chains/${chainId}/status`)
}

/** `X-APP-Auth: <pk>.<ts>.<sig>` over "APP-auditor-auth-v1\n{chainId}\n{app}\n{ts}" */
export async function authHeader(key: ZkKey, chainId: number, app: string): Promise<Record<string, string>> {
  const w = await loadWasm()
  const ts = Math.floor(Date.now() / 1000)
  const msg = `APP-auditor-auth-v1\n${chainId}\n${app.toLowerCase()}\n${ts}`
  const sig = w.sign_message(key.secret, new TextEncoder().encode(msg))
  return { 'X-APP-Auth': `${bytesToHex(key.pk)}.${ts}.${bytesToHex(sig)}` }
}

export async function getNotes(key: ZkKey, chainId: number, app: string): Promise<RemoteNote[]> {
  return request(`/chains/${chainId}/notes`, { headers: await authHeader(key, chainId, app) })
}

export async function getProof(key: ZkKey, chainId: number, app: string, index: number): Promise<RemoteProof> {
  return request(`/chains/${chainId}/proof/${index}`, { headers: await authHeader(key, chainId, app) })
}

export async function checkNullifiers(chainId: number, nullifiers: Hex[]): Promise<boolean[]> {
  if (nullifiers.length === 0) return []
  const r = await request<{ spent: boolean[] }>(`/chains/${chainId}/nullifiers/check`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ nullifiers }),
  })
  return r.spent
}
