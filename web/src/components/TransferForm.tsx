import { useState } from 'react'
import type { Hex } from '../lib/encoding'
import { formatAmount, parseAmount } from '../lib/encoding'
import { parseZkAddress } from '../lib/keys'
import { selectInputs, transfer } from '../lib/tx'
import type { ShieldedWallet, SyncState } from '../lib/sync'
import type { LogLine } from './Activity'
import { useOp } from './useOp'

const DECIMALS = 6
type Ctx = Parameters<typeof transfer>[0]

export function TransferForm({
  ctx,
  wallet,
  sync,
  onLog,
  onDone,
}: {
  ctx: Ctx
  wallet: ShieldedWallet
  sync: SyncState | null
  onLog: (t: string, l?: LogLine['level']) => void
  onDone: (h: Hex) => void
}) {
  const [to, setTo] = useState('')
  const [amount, setAmount] = useState('')
  const { busy, step, run } = useOp(onLog)

  let plan: string | null = null
  try {
    if (sync && amount) {
      const amt = parseAmount(amount, DECIMALS)
      const ins = selectInputs(sync.utxos, amt)
      const total = ins.reduce((s, u) => s + u.amount, 0n)
      plan = `Spends note${ins.length > 1 ? 's' : ''} #${ins.map((u) => u.index).join(', #')} (${formatAmount(total, DECIMALS)}), change ${formatAmount(total - amt, DECIMALS)} back to you.`
    }
  } catch (e) {
    plan = e instanceof Error ? e.message : String(e)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    let dest: Uint8Array
    let amt: bigint
    try {
      dest = parseZkAddress(to)
      amt = parseAmount(amount, DECIMALS)
      if (amt <= 0n) throw new Error('amount must be positive')
    } catch (err) {
      onLog(err instanceof Error ? err.message : String(err), 'err')
      return
    }
    if (!sync) return
    const h = await run('Transfer', (p) => transfer(ctx, wallet, dest, amt, p))
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
        <input id="transfer-to" className="mono" value={to} onChange={(e) => setTo(e.target.value)} placeholder="0x… (64 bytes)" spellCheck={false} />
      </label>
      <div className="row">
        <label>
          <span>Amount (tUSD)</span>
          <input id="transfer-amount" value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" />
        </label>
        <button className="primary" type="submit" disabled={busy || !sync}>
          {busy ? 'Working…' : 'Send privately'}
        </button>
      </div>
      {plan && <p className="hint">{plan}</p>}
      {step && (
        <div className="progress">
          <span className="dot" /> {step}
        </div>
      )}
    </form>
  )
}
