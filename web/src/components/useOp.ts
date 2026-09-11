import { useState } from 'react'
import { BaseError, ContractFunctionRevertedError } from 'viem'
import type { LogLine } from './Activity'

/** Human-readable reason for a failed operation, including custom contract errors. */
export function describeError(e: unknown): string {
  if (e instanceof BaseError) {
    const revert = e.walk((x) => x instanceof ContractFunctionRevertedError) as ContractFunctionRevertedError | null
    if (revert) {
      const name = revert.data?.errorName ?? revert.reason
      const args = revert.data?.args?.length ? `(${revert.data.args.map(String).join(', ')})` : ''
      return name ? `reverted: ${name}${args}` : revert.shortMessage
    }
    return e.shortMessage
  }
  return e instanceof Error ? e.message : String(e)
}

/** Run a long operation with a visible progress line and error reporting. */
export function useOp(onLog: (text: string, level?: LogLine['level']) => void) {
  const [busy, setBusy] = useState(false)
  const [step, setStep] = useState<string | null>(null)

  const run = async <T,>(label: string, fn: (progress: (s: string) => void) => Promise<T>): Promise<T | undefined> => {
    if (busy) return
    setBusy(true)
    setStep('Starting…')
    onLog(`${label} started`)
    try {
      const r = await fn((s) => {
        setStep(s)
        onLog(`${label}: ${s}`)
      })
      return r
    } catch (e) {
      onLog(`${label} failed: ${describeError(e)}`, 'err')
      return undefined
    } finally {
      setBusy(false)
      setStep(null)
    }
  }

  return { busy, step, run }
}
