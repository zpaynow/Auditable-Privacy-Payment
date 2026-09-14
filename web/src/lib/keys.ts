import { loadWasm } from './wasm'
import { bytesToHex, hexToBytes, type Hex } from './encoding'

/**
 * A BabyJubJub payment keypair. `pk` is the 64-byte x||y (LE) form used by the circuits and
 * services; `address` is the 32-byte compressed point (0x + 64 hex) that people share.
 */
export interface ZkKey {
  secret: Uint8Array // 32 bytes
  pk: Uint8Array // 64 bytes
  address: Hex // 0x + 64 hex: compressed public key, what you give to a payer
}

export async function keyFromSeed(seed: Uint8Array): Promise<ZkKey> {
  const w = await loadWasm()
  const kp = new w.WasmKeypair(seed)
  const secret = kp.secret_key()
  const pk = kp.public_key()
  kp.free()
  return { secret, pk, address: bytesToHex(w.compress_pk(pk)) }
}

export async function keyFromSecret(secret: Uint8Array): Promise<ZkKey> {
  const w = await loadWasm()
  const kp = w.WasmKeypair.from_secret(secret)
  const pk = kp.public_key()
  kp.free()
  return { secret, pk, address: bytesToHex(w.compress_pk(pk)) }
}

/** 64-byte public key -> 32-byte payment address (hex). */
export async function addressOf(pk: Uint8Array): Promise<Hex> {
  const w = await loadWasm()
  return bytesToHex(w.compress_pk(pk))
}

const STORAGE = 'app.zk.secret'

/**
 * The payment key is derived per (chain, pool contract), so a stored key is only valid for the
 * deployment it came from. It used to be kept unscoped, which meant switching chains in the UI
 * kept spending under the previous chain's identity: notes created that way belong to a key the
 * app will never derive again on that chain, and silently disappear from the wallet.
 */
interface StoredKey {
  secret: Hex
  chainId: number
  app: string
}

export function rememberKey(k: ZkKey, chainId: number, app: string) {
  try {
    const rec: StoredKey = { secret: bytesToHex(k.secret), chainId, app: app.toLowerCase() }
    sessionStorage.setItem(STORAGE, JSON.stringify(rec))
  } catch {
    /* private mode etc. */
  }
}

/** Returns the stored key only if it was derived for exactly this deployment. */
export async function recallKey(chainId: number, app: string): Promise<ZkKey | null> {
  try {
    const s = sessionStorage.getItem(STORAGE)
    if (!s) return null
    let rec: StoredKey
    try {
      rec = JSON.parse(s) as StoredKey
    } catch {
      // pre-scoping format: a bare secret with no record of its deployment. It cannot be
      // attributed safely, so drop it and make the user derive again.
      sessionStorage.removeItem(STORAGE)
      return null
    }
    if (!rec?.secret || rec.chainId !== chainId || rec.app?.toLowerCase() !== app.toLowerCase()) return null
    return await keyFromSecret(hexToBytes(rec.secret))
  } catch {
    return null
  }
}

export function forgetKey() {
  try {
    sessionStorage.removeItem(STORAGE)
  } catch {
    /* ignore */
  }
}

/** Accepts the 32-byte payment address (or, for compatibility, the raw 64-byte public key). */
export async function parseZkAddress(s: string): Promise<Uint8Array> {
  const b = hexToBytes(s.trim())
  if (b.length === 32) {
    const w = await loadWasm()
    return w.decompress_pk(b)
  }
  if (b.length === 64) return b
  throw new Error('payment address must be 0x + 64 hex characters')
}
