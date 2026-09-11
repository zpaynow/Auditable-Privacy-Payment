import { loadWasm } from './wasm'
import { bytesToHex, hexToBytes, type Hex } from './encoding'

/** A BabyJubJub payment keypair. `pk` is 64 bytes x||y (LE), the user's shielded address. */
export interface ZkKey {
  secret: Uint8Array // 32 bytes
  pk: Uint8Array // 64 bytes
  address: Hex // 0x + 128 hex, what you give to a payer
}

export async function keyFromSeed(seed: Uint8Array): Promise<ZkKey> {
  const w = await loadWasm()
  const kp = new w.WasmKeypair(seed)
  const secret = kp.secret_key()
  const pk = kp.public_key()
  kp.free()
  return { secret, pk, address: bytesToHex(pk) }
}

export async function keyFromSecret(secret: Uint8Array): Promise<ZkKey> {
  const w = await loadWasm()
  const kp = w.WasmKeypair.from_secret(secret)
  const pk = kp.public_key()
  kp.free()
  return { secret, pk, address: bytesToHex(pk) }
}

const STORAGE = 'app.zk.secret'

export function rememberKey(k: ZkKey) {
  try {
    sessionStorage.setItem(STORAGE, bytesToHex(k.secret))
  } catch {
    /* private mode etc. */
  }
}

export async function recallKey(): Promise<ZkKey | null> {
  try {
    const s = sessionStorage.getItem(STORAGE)
    if (!s) return null
    return await keyFromSecret(hexToBytes(s))
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

export function parseZkAddress(s: string): Uint8Array {
  const b = hexToBytes(s.trim())
  if (b.length !== 64) throw new Error('payment address must be 64 bytes (0x + 128 hex)')
  return b
}
