// Thin promise wrapper around the proving worker.
import type { ProveRequest, ProveResponse } from '../prover.worker'

let worker: Worker | null = null
let nextId = 1
const pending = new Map<number, { resolve: (v: { result: unknown; ms: number }) => void; reject: (e: Error) => void }>()

function getWorker(): Worker {
  if (!worker) {
    worker = new Worker(new URL('../prover.worker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (e: MessageEvent<ProveResponse>) => {
      const p = pending.get(e.data.id)
      if (!p) return
      pending.delete(e.data.id)
      if (e.data.ok) p.resolve({ result: e.data.result, ms: e.data.ms })
      else p.reject(new Error(e.data.error))
    }
    worker.onerror = (e) => {
      for (const p of pending.values()) p.reject(new Error(e.message))
      pending.clear()
    }
  }
  return worker
}

export function prove<T = unknown>(req: ProveRequest): Promise<{ result: T; ms: number }> {
  const id = nextId++
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve: resolve as (v: { result: unknown; ms: number }) => void, reject })
    getWorker().postMessage({ id, req })
  })
}

/** Start the worker early so the wasm module is compiled by the time the user proves. */
export function warmProver() {
  getWorker()
}
