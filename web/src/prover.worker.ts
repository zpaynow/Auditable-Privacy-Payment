/// <reference lib="webworker" />
// Proving worker: loads the wasm module once, fetches proving keys on demand
// (browser HTTP cache keeps them across reloads), and answers prove requests.
import init, * as w from './wasm/wasm.js'

export type ProveRequest =
  | {
      kind: 'deposit'
      asset: bigint
      amount: bigint
      ownerPk: Uint8Array
      blind: Uint8Array
      auditorPk: Uint8Array
      auditMemo: Uint8Array // 160
      auditShare: Uint8Array // 32
    }
  | {
      kind: 'transfer'
      shape: '2x2' | '1x2' | '2x3' | '1x3'
      secret: Uint8Array
      inputs: Uint8Array
      outputs: Uint8Array
      auditorPk: Uint8Array
      auditMemos: Uint8Array // 192 per output
    }
  | {
      kind: 'withdraw'
      secret: Uint8Array
      asset: bigint
      amount: bigint
      recipient: Uint8Array // 20
      fee: bigint
      inputBlind: Uint8Array
      ownerPk: Uint8Array
      merkleProof: Uint8Array // blob from WasmMerkleTree.proof
    }

export type ProveResponse =
  | { id: number; ok: true; result: unknown; ms: number }
  | { id: number; ok: false; error: string }

const MASK64 = (1n << 64n) - 1n
const lo = (n: bigint) => n & MASK64
const hi = (n: bigint) => n >> 64n

const wasmReady = init()
const keyCache = new Map<string, Promise<Uint8Array>>()

function loadKey(name: string): Promise<Uint8Array> {
  let p = keyCache.get(name)
  if (!p) {
    p = fetch(`/keys/${name}.pk`).then(async (r) => {
      if (!r.ok) throw new Error(`failed to fetch proving key ${name}: ${r.status}`)
      return new Uint8Array(await r.arrayBuffer())
    })
    keyCache.set(name, p)
  }
  return p
}

function seed(): Uint8Array {
  const s = new Uint8Array(32)
  crypto.getRandomValues(s)
  return s
}

async function prove(req: ProveRequest): Promise<unknown> {
  await wasmReady
  switch (req.kind) {
    case 'deposit': {
      const pk = await loadKey('deposit')
      const proof = w.deposit_prove(
        pk,
        req.asset,
        lo(req.amount),
        hi(req.amount),
        req.ownerPk,
        req.blind,
        req.auditorPk,
        req.auditMemo,
        req.auditShare,
        seed(),
      )
      return { proofEvm: w.proof_to_evm(proof) }
    }
    case 'transfer': {
      const pk = await loadKey(`transfer_${req.shape}`)
      return w.transfer_prove(pk, req.secret, req.inputs, req.outputs, req.auditorPk, req.auditMemos, seed())
    }
    case 'withdraw': {
      const pk = await loadKey('withdraw')
      const mp = req.merkleProof
      const nodes = mp.slice(0, 20 * 64)
      const root = mp.slice(1280, 1312)
      const dv = new DataView(mp.buffer, mp.byteOffset)
      const version = dv.getUint32(1312, true)
      const index = dv.getUint32(1316, true)
      const ledger = dv.getUint32(1320, true)
      const proof = w.withdraw_prove(
        pk,
        req.secret,
        req.asset,
        lo(req.amount),
        hi(req.amount),
        req.recipient,
        lo(req.fee),
        hi(req.fee),
        req.asset,
        lo(req.amount),
        hi(req.amount),
        req.ownerPk,
        req.inputBlind,
        nodes,
        ledger,
        root,
        version,
        index,
        seed(),
      )
      return { proofEvm: w.proof_to_evm(proof) }
    }
  }
}

self.onmessage = async (e: MessageEvent<{ id: number; req: ProveRequest }>) => {
  const { id, req } = e.data
  const t0 = performance.now()
  try {
    const result = await prove(req)
    const msg: ProveResponse = { id, ok: true, result, ms: Math.round(performance.now() - t0) }
    self.postMessage(msg)
  } catch (err) {
    const msg: ProveResponse = { id, ok: false, error: err instanceof Error ? err.message : String(err) }
    self.postMessage(msg)
  }
}
