// Byte helpers shared by the UI, the sync engine and the prover worker.
// Conventions (see wasm/README.md): field elements are 32-byte arkworks little-endian
// unless a name says `evm` (big-endian bytes32 / uint256). Amounts are u128 split into two u64.

export type Hex = `0x${string}`

export const MASK64 = (1n << 64n) - 1n

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex
  if (h.length % 2) throw new Error('odd hex length')
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function bytesToHex(b: Uint8Array): Hex {
  let s = '0x'
  for (const x of b) s += x.toString(16).padStart(2, '0')
  return s as Hex
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(len)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

export function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, n, true)
  return b
}

export function u128le(n: bigint): Uint8Array {
  return concat(u64le(n & MASK64), u64le(n >> 64n))
}

export function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, true)
  return b
}

export function readU64le(b: Uint8Array, off: number): bigint {
  return new DataView(b.buffer, b.byteOffset + off, 8).getBigUint64(0, true)
}

export function readU128le(b: Uint8Array, off: number): bigint {
  return readU64le(b, off) | (readU64le(b, off + 8) << 64n)
}

export function readU32le(b: Uint8Array, off: number): number {
  return new DataView(b.buffer, b.byteOffset + off, 4).getUint32(0, true)
}

export const lo = (n: bigint) => n & MASK64
export const hi = (n: bigint) => n >> 64n

/** uint256 (bigint) -> 32-byte big-endian */
export function bigintToBe32(n: bigint): Uint8Array {
  return hexToBytes(n.toString(16).padStart(64, '0'))
}

/** 32-byte big-endian -> bigint */
export function be32ToBigint(b: Uint8Array): bigint {
  return BigInt(bytesToHex(b))
}

/** 20-byte address bytes */
export function addressToBytes(addr: string): Uint8Array {
  const b = hexToBytes(addr)
  if (b.length !== 20) throw new Error('address must be 20 bytes')
  return b
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}

/** "12.5" with 6 decimals -> 12500000n */
export function parseAmount(s: string, decimals: number): bigint {
  const t = s.trim()
  if (!/^\d+(\.\d+)?$/.test(t)) throw new Error('invalid amount')
  const [w, f = ''] = t.split('.')
  if (f.length > decimals) throw new Error(`at most ${decimals} decimals`)
  return BigInt(w) * 10n ** BigInt(decimals) + BigInt((f + '0'.repeat(decimals)).slice(0, decimals) || '0')
}

export function formatAmount(n: bigint, decimals: number): string {
  const s = n.toString().padStart(decimals + 1, '0')
  const w = s.slice(0, -decimals) || '0'
  const f = s.slice(-decimals).replace(/0+$/, '')
  return f ? `${w}.${f}` : w
}

export function short(hex: string, n = 6): string {
  return hex.length > 2 * n + 2 ? `${hex.slice(0, n + 2)}…${hex.slice(-n)}` : hex
}
