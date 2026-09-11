import { useState } from 'react'
import { isAddress } from 'viem'
import type { Hex } from '../lib/encoding'
import { formatAmount, short } from '../lib/encoding'
import { withdraw } from '../lib/tx'
import type { ShieldedWallet, SyncState } from '../lib/sync'
import type { LogLine } from './Activity'
import { useOp } from './useOp'

const DECIMALS = 6
type Ctx = Parameters<typeof withdraw>[0]

export function WithdrawForm({
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
  const [recipient, setRecipient] = useState<string>(ctx.account)
  const [selected, setSelected] = useState<number | null>(null)
  const { busy, step, run } = useOp(onLog)
  const live = sync?.utxos.filter((u) => !u.spent && !u.frozen) ?? []
  const note = live.find((u) => u.index === selected) ?? null

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!note) {
      onLog('Select a note to withdraw', 'err')
      return
    }
    if (!isAddress(recipient)) {
      onLog('Recipient must be an EVM address', 'err')
      return
    }
    const h = await run('Withdraw', (p) => withdraw(ctx, wallet, note, recipient as Hex, p))
    if (h) {
      onDone(h)
      setSelected(null)
    }
  }

  return (
    <form className="stack" onSubmit={submit}>
      <p className="hint">
        Unshields one whole note to a public address. The recipient is bound into the proof, so a copied transaction
        cannot be redirected.
      </p>
      <div className="tbl">
        {live.length === 0 ? (
          <p className="empty">No spendable notes.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th></th>
                <th>#</th>
                <th className="num">Amount</th>
                <th>Commitment</th>
              </tr>
            </thead>
            <tbody>
              {live.map((u) => (
                <tr key={u.index} className={`selectable ${selected === u.index ? 'selected' : ''}`} onClick={() => setSelected(u.index)}>
                  <td>
                    <input type="radio" name="note" id={`note-${u.index}`} checked={selected === u.index} onChange={() => setSelected(u.index)} />
                  </td>
                  <td>{u.index}</td>
                  <td className="num">{formatAmount(u.amount, DECIMALS)}</td>
                  <td className="mono">{short(u.commitment, 6)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="row">
        <label>
          <span>Recipient address</span>
          <input id="withdraw-recipient" className="mono" value={recipient} onChange={(e) => setRecipient(e.target.value)} spellCheck={false} />
        </label>
        <button className="primary" type="submit" disabled={busy || !note}>
          {busy ? 'Working…' : note ? `Withdraw ${formatAmount(note.amount, DECIMALS)} tUSD` : 'Withdraw'}
        </button>
      </div>
      {step && (
        <div className="progress">
          <span className="dot" /> {step}
        </div>
      )}
    </form>
  )
}
