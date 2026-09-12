import { useState } from 'react'
import type { Hex } from '../lib/encoding'
import { formatAmount, parseAmount } from '../lib/encoding'
import { parseZkAddress } from '../lib/keys'
import { selectInputs, transfer, transferViaAggregator } from '../lib/tx'
import { useAggregator } from './useAggregator'
import type { NoteSource, SyncState } from '../lib/sync'
import type { LogLine } from './Activity'
import { useOp } from './useOp'

type Ctx = Parameters<typeof transfer>[0]

export function TransferForm({
  ctx,
  wallet,
  sync,
  onLog,
  onDone,
}: {
  ctx: Ctx
  wallet: NoteSource
  sync: SyncState | null
  onLog: (t: string, l?: LogLine['level']) => void
  onDone: (h: Hex) => void
}) {
  const DECIMALS = ctx.token.decimals
  const SYMBOL = ctx.token.symbol
  const [to, setTo] = useState('')
  const [amount, setAmount] = useState('')
  const [viaAgg, setViaAgg] = useState(false)
  const { busy, step, run } = useOp(onLog)
  const agg = useAggregator(ctx.publicClient.chain?.id ?? 0)
  const useAgg = viaAgg && agg.info !== null
  const aggFee = agg.info ? BigInt(agg.info.transfer_fee) : 0n

  let plan: string | null = null
  try {
    if (sync && amount) {
      const amt = parseAmount(amount, DECIMALS)
      const need = useAgg ? amt + aggFee : amt
      const ins = selectInputs(sync.utxos, need)
      const total = ins.reduce((s, u) => s + u.amount, 0n)
      plan = `Spends note${ins.length > 1 ? 's' : ''} #${ins.map((u) => u.index).join(', #')} (${formatAmount(total, DECIMALS)}), change ${formatAmount(total - need, DECIMALS)} back to you${useAgg ? `, fee ${formatAmount(aggFee, DECIMALS)} to the aggregator` : ''}.`
    }
  } catch (e) {
    plan = e instanceof Error ? e.message : String(e)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    let dest: Uint8Array
    let amt: bigint
    try {
      dest = await parseZkAddress(to)
      amt = parseAmount(amount, DECIMALS)
      if (amt <= 0n) throw new Error('amount must be positive')
    } catch (err) {
      onLog(err instanceof Error ? err.message : String(err), 'err')
      return
    }
    if (!sync) return
    const h = await run(useAgg ? 'Transfer via aggregator' : 'Transfer', (p) =>
      useAgg ? transferViaAggregator(ctx, wallet, dest, amt, agg.info!, p) : transfer(ctx, wallet, dest, amt, p),
    )
    if (h) {
      onDone(h)
      setAmount('')
    }
  }

  return (
    <form className="stack" onSubmit={submit}>
      <p className="hint">
        Sends shielded value to another payment address. On-chain observers see only nullifiers, new commitments and
        encrypted memos. Up to two of your notes are combined per transfer.
      </p>
      <label>
        <span>Recipient payment address</span>
        <input id="transfer-to" className="mono" value={to} onChange={(e) => setTo(e.target.value)} placeholder="0x… (64 hex characters)" spellCheck={false} />
      </label>
      <div className="row">
        <label>
          <span>Amount ({SYMBOL})</span>
          <input id="transfer-amount" value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" />
        </label>
        <button className="primary" type="submit" disabled={busy || !sync}>
          {busy ? 'Working…' : 'Send privately'}
        </button>
      </div>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <input id="transfer-via-agg" type="checkbox" style={{ width: 'auto' }} checked={useAgg} disabled={!agg.info} onChange={(e) => setViaAgg(e.target.checked)} />
        <span>
          Send through the aggregator: no wallet transaction, fee{' '}
          {agg.info ? `${formatAmount(aggFee, DECIMALS)} ${SYMBOL} paid from your notes` : 'unavailable'}
          {agg.error && <span style={{ color: 'var(--ink-3)' }}> ({agg.error})</span>}
        </span>
      </label>
      {plan && <p className="hint">{plan}</p>}
      {step && (
        <div className="progress">
          <span className="dot" /> {step}
        </div>
      )}
    </form>
  )
}
