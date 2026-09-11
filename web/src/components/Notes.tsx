import { useState } from 'react'
import type { SyncState } from '../lib/sync'
import { formatAmount, short } from '../lib/encoding'

const DECIMALS = 6
const SYMBOL = 'tUSD'

export function Notes({
  keyAddress,
  sync,
  syncing,
  syncError,
  onRefresh,
}: {
  keyAddress: string
  sync: SyncState | null
  syncing: boolean
  syncError: string | null
  onRefresh: () => void
}) {
  const [copied, setCopied] = useState(false)
  const live = sync?.utxos.filter((u) => !u.spent) ?? []
  const spendable = live.filter((u) => !u.frozen).reduce((s, u) => s + u.amount, 0n)
  const frozen = live.filter((u) => u.frozen).reduce((s, u) => s + u.amount, 0n)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(keyAddress)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard blocked */
    }
  }

  return (
    <section className="card">
      <header>
        <h2>Shielded balance</h2>
        <span className={`pill ${syncError ? 'crit' : syncing ? 'warn' : 'ok'}`}>
          {syncError ? 'sync error' : syncing ? 'syncing…' : sync ? `synced · block ${sync.lastBlock}` : 'not synced'}
        </span>
      </header>

      <div className="balance">
        <div className="amount">
          {formatAmount(spendable, DECIMALS)}
          <small>{SYMBOL}</small>
        </div>
        {frozen > 0n && <p className="hint">{formatAmount(frozen, DECIMALS)} {SYMBOL} frozen by the auditor</p>}
      </div>

      <div>
        <p className="hint" style={{ marginBottom: 4 }}>Your payment address (share this to receive)</p>
        <div className="addr" title={keyAddress}>{keyAddress}</div>
        <div className="row" style={{ marginTop: 8 }}>
          <button onClick={copy} style={{ flex: '0 0 auto' }}>{copied ? 'Copied' : 'Copy address'}</button>
          <button onClick={onRefresh} disabled={syncing} style={{ flex: '0 0 auto' }}>Refresh</button>
        </div>
      </div>

      <dl className="kv">
        <dt>Notes in pool</dt>
        <dd>{sync?.count ?? '–'}</dd>
        <dt>Tree root</dt>
        <dd className="mono">{sync ? short(sync.root, 8) : '–'}</dd>
      </dl>
      {syncError && <p className="hint" style={{ color: 'var(--crit)' }}>{syncError}</p>}

      <div className="tbl">
        {live.length === 0 ? (
          <p className="empty">No unspent notes yet. Deposit to create one, or receive a transfer.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th className="num">Amount</th>
                <th>Commitment</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {live.map((u) => (
                <tr key={u.index}>
                  <td>{u.index}</td>
                  <td className="num">{formatAmount(u.amount, DECIMALS)}</td>
                  <td className="mono">{short(u.commitment, 6)}</td>
                  <td>{u.frozen ? <span className="pill crit">frozen</span> : <span className="pill ok">spendable</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}
