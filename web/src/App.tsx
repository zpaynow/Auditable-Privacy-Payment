import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useAccount, useChainId, useConnect, useDisconnect, usePublicClient, useSignMessage, useSwitchChain, useWalletClient } from 'wagmi'
import type { Hex } from './lib/encoding'
import { deployments, ZK_KEY_MESSAGE, chains } from './lib/config'
import { forgetKey, keyFromSeed, recallKey, rememberKey, type ZkKey } from './lib/keys'
import { ShieldedWallet, type SyncState } from './lib/sync'
import { warmProver } from './lib/prover'
import { hexToBytes, short } from './lib/encoding'
import { Notes } from './components/Notes'
import { DepositForm } from './components/DepositForm'
import { TransferForm } from './components/TransferForm'
import { WithdrawForm } from './components/WithdrawForm'
import { AuditorPanel } from './components/AuditorPanel'
import { Activity, type LogLine } from './components/Activity'

type Tab = 'deposit' | 'transfer' | 'withdraw' | 'auditor'

export default function App() {
  const { address, isConnected } = useAccount()
  const chainId = useChainId()
  const { connect, connectors, isPending: connecting } = useConnect()
  const { disconnect } = useDisconnect()
  const { switchChain } = useSwitchChain()
  const publicClient = usePublicClient()
  const { data: walletClient } = useWalletClient()
  const { signMessageAsync } = useSignMessage()

  const deployment = deployments[chainId]
  const [key, setKey] = useState<ZkKey | null>(null)
  const [deriving, setDeriving] = useState(false)
  const walletRef = useRef<ShieldedWallet | null>(null)
  const [sync, setSync] = useState<SyncState | null>(null)
  const [syncing, setSyncing] = useState(false)
  const [syncError, setSyncError] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('deposit')
  const [log, setLog] = useState<LogLine[]>([])

  const pushLog = useCallback((text: string, level: LogLine['level'] = 'info') => {
    setLog((l) => [{ t: Date.now(), text, level }, ...l].slice(0, 200))
  }, [])

  useEffect(() => {
    warmProver()
    recallKey().then((k) => k && setKey(k))
  }, [])

  // (re)create the shielded wallet whenever key / chain / contract changes
  useEffect(() => {
    walletRef.current = null
    setSync(null)
    setSyncError(null)
    if (!key || !publicClient || !deployment) return
    walletRef.current = new ShieldedWallet(publicClient, deployment.app, key, deployment.deployBlock)
  }, [key, publicClient, deployment])

  const doSync = useCallback(async () => {
    const w = walletRef.current
    if (!w || syncing) return
    setSyncing(true)
    try {
      const s = await w.sync()
      setSync(s)
      setSyncError(null)
    } catch (e) {
      setSyncError(e instanceof Error ? e.message : String(e))
    } finally {
      setSyncing(false)
    }
  }, [syncing])

  useEffect(() => {
    if (!walletRef.current) return
    void doSync()
    const id = setInterval(() => void doSync(), 15_000)
    return () => clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, deployment, publicClient])

  const deriveKey = async () => {
    if (!deployment) return
    setDeriving(true)
    try {
      const sig = await signMessageAsync({ message: ZK_KEY_MESSAGE(chainId, deployment.app) })
      const k = await keyFromSeed(hexToBytes(sig))
      rememberKey(k)
      setKey(k)
      pushLog(`Payment key derived: ${short(k.address, 8)}`, 'ok')
    } catch (e) {
      pushLog(e instanceof Error ? e.message : String(e), 'err')
    } finally {
      setDeriving(false)
    }
  }

  const ctx = useMemo(() => {
    if (!publicClient || !walletClient || !deployment || !key || !address) return null
    return { publicClient, walletClient, deployment, key, account: address as Hex }
  }, [publicClient, walletClient, deployment, key, address])

  const afterTx = (hash: Hex, what: string) => {
    pushLog(`${what} confirmed · ${short(hash, 8)}`, 'ok')
    void doSync()
  }

  return (
    <>
      <header className="top">
        <div className="brand">
          <h1>Auditable Privacy Payment</h1>
          <small>testnet · phase 1</small>
        </div>
        <div className="wallet">
          {isConnected ? (
            <>
              <select
                id="chain"
                value={chainId}
                onChange={(e) => switchChain({ chainId: Number(e.target.value) as (typeof chains)[number]['id'] })}
                style={{ width: 'auto' }}
              >
                {chains.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
              <span className="pill muted mono">{short(address!, 5)}</span>
              {deployment ? (
                <span className="pill ok">contract {short(deployment.app, 4)}</span>
              ) : (
                <span className="pill crit">no deployment on this chain</span>
              )}
              <button onClick={() => { disconnect(); forgetKey(); setKey(null) }}>Disconnect</button>
            </>
          ) : (
            connectors.map((c) => (
              <button key={c.uid} className="primary" disabled={connecting} onClick={() => connect({ connector: c })}>
                Connect {c.name}
              </button>
            ))
          )}
        </div>
      </header>

      {!isConnected && (
        <section className="card">
          <h2>Connect a wallet to begin</h2>
          <p className="hint">
            Your wallet signs one message to derive a private payment key. Proofs are generated in this browser; nothing
            secret is sent anywhere.
          </p>
        </section>
      )}

      {isConnected && deployment && !key && (
        <section className="card">
          <h2>Derive your payment key</h2>
          <p className="hint">
            One signature, deterministic per wallet and contract. Anyone who can produce this signature can spend your
            shielded notes.
          </p>
          <div>
            <button className="primary" disabled={deriving} onClick={deriveKey}>
              {deriving ? 'Waiting for signature…' : 'Sign & derive key'}
            </button>
          </div>
        </section>
      )}

      {isConnected && deployment && key && (
        <div className="layout">
          <div style={{ display: 'grid', gap: 20 }}>
            <Notes
              keyAddress={key.address}
              sync={sync}
              syncing={syncing}
              syncError={syncError}
              onRefresh={doSync}
            />
            <Activity lines={log} />
          </div>

          <section className="card">
            <div className="tabs" role="tablist">
              {(['deposit', 'transfer', 'withdraw', 'auditor'] as Tab[]).map((t) => (
                <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}>
                  {t[0].toUpperCase() + t.slice(1)}
                </button>
              ))}
            </div>
            {ctx && walletRef.current && (
              <>
                {tab === 'deposit' && <DepositForm ctx={ctx} onLog={pushLog} onDone={(h) => afterTx(h, 'Deposit')} />}
                {tab === 'transfer' && (
                  <TransferForm ctx={ctx} wallet={walletRef.current} sync={sync} onLog={pushLog} onDone={(h) => afterTx(h, 'Transfer')} />
                )}
                {tab === 'withdraw' && (
                  <WithdrawForm ctx={ctx} wallet={walletRef.current} sync={sync} onLog={pushLog} onDone={(h) => afterTx(h, 'Withdraw')} />
                )}
                {tab === 'auditor' && <AuditorPanel ctx={ctx} onLog={pushLog} />}
              </>
            )}
          </section>
        </div>
      )}
    </>
  )
}
