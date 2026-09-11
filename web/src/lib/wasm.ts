// Main-thread wasm instance for cheap operations (keys, memos, tree, encoding).
// Heavy proving runs in prover.worker.ts with its own instance.
import init, * as wasm from '../wasm/wasm.js'

let ready: Promise<typeof wasm> | null = null

export function loadWasm(): Promise<typeof wasm> {
  if (!ready) ready = init().then(() => wasm)
  return ready
}

export type Wasm = typeof wasm
