import { useEffect, useState } from 'react'
import type { Hex } from '../lib/encoding'
import { formatAmount, hexToBytes, short } from '../lib/encoding'
import { auditScan, type AuditRow } from '../lib/sync'
import { setFrozen } from '../lib/tx'
import { appAbi } from '../lib/config'
import type { LogLine } from './Activity'
import { useOp } from './useOp'

const DECIMALS = 6
type Ctx = Parameters<typeof setFrozen>[0]

export function AuditorPanel({ ctx, onLog }: { ctx: Ctx; onLog: (t: string, l?: LogLine['level']) => void }) {
  const [secret, setSecret] = useState('')
  const [rows, setRows] = useState<(AuditRow & { frozen: boolean })[] | null>(null)
  const [scope, setScope] = useState<'session' | 'last' | 'all'>('session')
  const [lastN, setLastN] = useState('10')
  // block height when this tab was opened: "session" scope only decrypts notes created after it
  const [sinceBlock, setSinceBlock] = useState<bigint | null>(null)
  const { busy, step, run } = useOp(onLog)
  const isAdmin = ctx.account.toLowerCase() === ctx.deployment.auditorAdmin.toLowerCase()

  useEffect(() => {
    ctx.publicClient.getBlockNumber().then((b) => setSinceBlock(b + 1n)).catch(() => setSinceBlock(0n))
  }, [ctx.publicClient])

  const scan = async (e: React.FormEvent) => {
    e.preventDefault()
    let sk: Uint8Array
    try {
      sk = hexToBytes(secret.trim())
      if (sk.length !== 32) throw new Error('auditor secret must be 32 bytes')
    } catch (err) {
      onLog(err instanceof Error ? err.message : String(err), 'err')
      return
    }
    const fromBlock = scope === 'session' ? (sinceBlock ?? 0n) : BigInt(ctx.deployment.deployBlock)
    const limit = scope === 'last' ? Math.max(1, Number(lastN) || 10) : undefined
    const r = await run('Audit scan', async (p) => {
      p(scope === 'session' ? `Decrypting notes created since block ${fromBlock}…` : scope === 'last' ? `Decrypting the last ${limit} notes…` : 'Decrypting every note in the pool…')
      const rs = await auditScan(ctx.publicClient, ctx.deployment.app, fromBlock, sk, limit)
      p('Reading freeze status…')
      const frozen = await Promise.all(
        rs.map((row) =>
          row.freezer === '0x'
            ? Promise.resolve(false)
            : (ctx.publicClient.readContract({ address: ctx.deployment.app, abi: appAbi, functionName: 'frozen', args: [BigInt(row.freezer)] }) as Promise<boolean>),
        ),
      )
      return rs.map((row, i) => ({ ...row, frozen: frozen[i] }))
    })
    if (r) {
      setRows(r)
      onLog(`Audit scan: ${r.length} note${r.length === 1 ? '' : 's'}, ${r.filter((x) => x.amount >= 0n).length} decrypted`, 'ok')
    }
  }

  const toggle = async (row: AuditRow & { frozen: boolean }) => {
    const h = await run(row.frozen ? 'Unfreeze' : 'Freeze', (p) => setFrozen(ctx, row.freezer as Hex, !row.frozen, p))
    if (h) {
      onLog(`Note #${row.index} ${row.frozen ? 'unfrozen' : 'frozen'}`, 'ok')
      setRows((rs) => rs?.map((r) => (r.index === row.index ? { ...r, frozen: !row.frozen } : r)) ?? null)
    }
  }

  return (
    <div className="stack" style={{ display: 'grid', gap: 12 }}>
      <p className="hint">
        With the auditor secret, every note in the pool can be opened: asset, amount and owner. The auditor admin
        address ({short(ctx.deployment.auditorAdmin, 4)}) can freeze a note so it cannot be spent.
        {isAdmin ? ' You are the auditor admin.' : ' Connect that wallet to freeze.'}
      </p>
      <form className="stack" onSubmit={scan}>
        <div className="row">
          <label>
            <span>Auditor secret (32 bytes, from app-tools keygen)</span>
            <input id="auditor-secret" className="mono" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} spellCheck={false} />
          </label>
          <button className="primary" type="submit" disabled={busy}>
            {busy ? 'Working…' : 'Scan'}
          </button>
        </div>
        <div className="row" style={{ alignItems: 'center', fontSize: 13 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, flex: '0 0 auto' }}>
            <input type="radio" name="scope" id="scope-session" style={{ width: 'auto' }} checked={scope === 'session'} onChange={() => setScope('session')} />
            <span>Since this tab opened{sinceBlock !== null ? ` (block ${sinceBlock})` : ''}</span>
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, flex: '0 0 auto' }}>
            <input type="radio" name="scope" id="scope-last" style={{ width: 'auto' }} checked={scope === 'last'} onChange={() => setScope('last')} />
            <span>Last</span>
            <input id="scope-last-n" value={lastN} onChange={(e) => setLastN(e.target.value)} inputMode="numeric" style={{ width: 56, padding: '2px 6px' }} onFocus={() => setScope('last')} />
            <span>notes</span>
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, flex: '0 0 auto' }}>
            <input type="radio" name="scope" id="scope-all" style={{ width: 'auto' }} checked={scope === 'all'} onChange={() => setScope('all')} />
            <span>Everything</span>
          </label>
        </div>
      </form>
      {step && (
        <div className="progress">
          <span className="dot" /> {step}
        </div>
      )}
      {rows && rows.length === 0 && <p className="empty">No notes in this range yet. Make a deposit or transfer, then scan again.</p>}
      {rows && rows.length > 0 && (
        <div className="tbl">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th className="num">Amount</th>
                <th>Owner</th>
                <th>Commitment</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.index}>
                  <td>{r.index}</td>
                  <td className="num">{r.amount < 0n ? <span className="pill warn">undecryptable</span> : formatAmount(r.amount, DECIMALS)}</td>
                  <td className="mono" title={r.ownerAddress}>{r.ownerAddress === '0x' ? '–' : short(r.ownerAddress, 6)}</td>
                  <td className="mono">{short(r.commitment, 6)}</td>
                  <td>{r.frozen ? <span className="pill crit">frozen</span> : <span className="pill ok">active</span>}</td>
                  <td>
                    {r.amount >= 0n && (
                      <button type="button" disabled={busy || !isAdmin} onClick={() => toggle(r)}>
                        {r.frozen ? 'Unfreeze' : 'Freeze'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
