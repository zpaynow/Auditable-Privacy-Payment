import { useEffect, useState } from 'react'
import { getInfo, type AggregatorInfo, AGGREGATOR_URL } from '../lib/aggregator'

/** Aggregator quote for the current chain, or null when the service is unreachable / on another chain. */
export function useAggregator(chainId: number) {
  const [info, setInfo] = useState<AggregatorInfo | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let alive = true
    getInfo()
      .then((i) => {
        if (!alive) return
        if (i.chain_id !== chainId) {
          setError(`aggregator at ${AGGREGATOR_URL} serves chain ${i.chain_id}`)
          setInfo(null)
        } else {
          setInfo(i)
          setError(null)
        }
      })
      .catch((e) => {
        if (!alive) return
        setInfo(null)
        setError(e instanceof Error ? e.message : String(e))
      })
    return () => {
      alive = false
    }
  }, [chainId])
  return { info, error }
}
