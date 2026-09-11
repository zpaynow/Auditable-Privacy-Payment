import { useEffect, useState } from 'react'
import type { Hex } from '../lib/encoding'
import { formatAmount, parseAmount } from '../lib/encoding'
import { deposit, mintTestToken } from '../lib/tx'
import { tokenAbi } from '../lib/config'
import type { LogLine } from './Activity'
import { useOp } from './useOp'

const DECIMALS = 6

type Ctx = Parameters<typeof deposit>[0]

export function DepositForm({ ctx, onLog, onDone }: { ctx: Ctx; onLog: (t: string, l?: LogLine['level']) => void; onDone: (h: Hex) => void }) {
  const [amount, setAmount] = useState('100')
  const [balance, setBalance] = useState<bigint | null>(null)
  const { busy, step, run } = useOp(onLog)

  const refreshBalance = async () => {
    const b = (await ctx.publicClient.readContract({
      address: ctx.deployment.token,
      abi: tokenAbi,
      functionName: 'balanceOf',
      args: [ctx.account],
    })) as bigint
    setBalance(b)
  }
  useEffect(() => {
    void refreshBalance()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ctx.account, ctx.deployment.token])

  let parsed: bigint | null = null
  try {
    parsed = parseAmount(amount || '0', DECIMALS)
  } catch {
    parsed = null
  }
  const insufficient = parsed !== null && balance !== null && parsed > balance

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    let amt: bigint
    try {
      amt = parseAmount(amount, DECIMALS)
      if (amt <= 0n) throw new Error('amount must be positive')
      if (balance !== null && amt > balance) throw new Error('not enough public tUSD: mint from the faucet first')
    } catch (err) {
      onLog(err instanceof Error ? err.message : String(err), 'err')
      return
    }
    const h = await run('Deposit', (p) => deposit(ctx, amt, p))
    if (h) {
      onDone(h)
      void refreshBalance()
    }
  }

  const mint = async () => {
    const h = await run('Mint test tokens', (p) => mintTestToken(ctx, 1_000n * 10n ** BigInt(DECIMALS), p))
    if (h) {
      onLog('Minted 1000 tUSD', 'ok')
      void refreshBalance()
    }
  }

  return (
    <form className="stack" onSubmit={submit}>
      <p className="hint">
        Locks tokens in the pool and creates one shielded note owned by your payment key. The auditor receives an
        encrypted copy of the note.
      </p>
      <dl className="kv">
        <dt>Public balance</dt>
        <dd>
          {balance === null ? '…' : `${formatAmount(balance, DECIMALS)} tUSD`}{' '}
          <button type="button" onClick={mint} disabled={busy} style={{ padding: '2px 8px', marginLeft: 8 }}>
            Mint 1000 (faucet)
          </button>
        </dd>
      </dl>
      <div className="row">
        <label>
          <span>Amount (tUSD)</span>
          <input id="deposit-amount" value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" />
        </label>
        <button className="primary" type="submit" disabled={busy || insufficient}>
          {busy ? 'Working…' : 'Deposit'}
        </button>
      </div>
      {insufficient && <p className="hint" style={{ color: 'var(--warn)' }}>Not enough public tUSD for this amount. Mint from the faucet first.</p>}
      {step && (
        <div className="progress">
          <span className="dot" /> {step}
        </div>
      )}
    </form>
  )
}
