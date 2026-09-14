import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useAccount, useChainId, useConnect, useDisconnect, usePublicClient, useSignMessage, useSwitchChain, useWalletClient } from 'wagmi'
import type { Hex } from './lib/encoding'
import { deployments, ZK_KEY_MESSAGE, chains, chainGroupLabel, isTestnet, tokenAbi, type TokenMeta } from './lib/config'
import { forgetKey, keyFromSeed, recallKey, rememberKey, type ZkKey } from './lib/keys'
import { RemoteWallet, ShieldedWallet, type NoteSource, type SyncState } from './lib/sync'
import { getStatus } from './lib/auditorClient'
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
  const { address, isConnected, chainId: walletChainId } = useAccount()
  const chainId = useChainId()
  const { connect, connectors, isPending: connecting } = useConnect()
  const { disconnect } = useDisconnect()
  const { switchChain } = useSwitchChain()
  const publicClient = usePublicClient()
  const { data: walletClient } = useWalletClient()
  const { signMessageAsync } = useSignMessage()

  const deployment = deployments[chainId]
  const chain = chains.find((c) => c.id === chainId)
  // testnets get a banner, a badge and a tagged tab title so nobody mistakes them for production
  const testnet = isTestnet(chainId)
  useEffect(() => {
    document.title = testnet ? `[TESTNET] Auditable Privacy Payment` : 'Auditable Privacy Payment'
  }, [testnet])
  // the wallet is on a network we do not support (or has not switched yet): wagmi falls back to the
  // default chain for chainId, but no wallet client is available until the user switches
  const wrongChain = isConnected && walletChainId !== chainId
  const [key, setKey] = useState<ZkKey | null>(null)
  const [deriving, setDeriving] = useState(false)
  const walletRef = useRef<NoteSource | null>(null)
  const [sync, setSync] = useState<SyncState | null>(null)
  const [syncing, setSyncing] = useState(false)
  const [syncError, setSyncError] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('deposit')
  const [log, setLog] = useState<LogLine[]>([])
  const [token, setToken] = useState<TokenMeta | null>(null)

  // symbol / decimals of the registered token on the current chain
  useEffect(() => {
    setToken(null)
    if (!publicClient || !deployment) return
    let alive = true
    Promise.all([
      publicClient.readContract({ address: deployment.token, abi: tokenAbi, functionName: 'symbol' }),
      publicClient.readContract({ address: deployment.token, abi: tokenAbi, functionName: 'decimals' }),
    ])
      .then(([symbol, decimals]) => alive && setToken({ symbol: String(symbol), decimals: Number(decimals) }))
      .catch(() => alive && setToken({ symbol: 'TOKEN', decimals: 18 }))
    return () => {
      alive = false
    }
  }, [publicClient, deployment])

  const pushLog = useCallback((text: string, level: LogLine['level'] = 'info') => {
    setLog((l) => [{ t: Date.now(), text, level }, ...l].slice(0, 200))
  }, [])

  useEffect(() => {
    warmProver()
  }, [])

  // The payment key belongs to one (chain, contract). Drop it the moment either changes, so a
  // chain switch can never spend or deposit under the previous chain's identity, and restore the
  // stored key only when it was derived for the deployment now selected.
  useEffect(() => {
    setKey(null)
    if (!deployment) return
    let cancelled = false
    void recallKey(chainId, deployment.app).then((k) => {
      if (!cancelled && k) setKey(k)
    })
    return () => {
      cancelled = true
    }
  }, [chainId, deployment])

  // (re)create the wallet whenever key / chain / contract changes: prefer the auditor service
  // (no chain scan, no local tree), fall back to scanning the chain ourselves
  const [sourceReady, setSourceReady] = useState(0)
  useEffect(() => {
    walletRef.current = null
    setSync(null)
    setSyncError(null)
    if (!key || !publicClient || !deployment) return
    let alive = true
    getStatus(chainId)
      .then((st) => {
        if (!alive) return
        if (st.chain_id === chainId && st.app.toLowerCase() === deployment.app.toLowerCase()) {
          walletRef.current = new RemoteWallet(key, chainId, deployment.app)
        } else {
          walletRef.current = new ShieldedWallet(publicClient, deployment.app, key, deployment.deployBlock)
        }
      })
      .catch(() => {
        if (!alive) return
        walletRef.current = new ShieldedWallet(publicClient, deployment.app, key, deployment.deployBlock)
      })
      .finally(() => alive && setSourceReady((n) => n + 1))
    return () => {
      alive = false
    }
  }, [key, publicClient, deployment, chainId])

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
  }, [sourceReady])

  const deriveKey = async () => {
    if (!deployment) return
    setDeriving(true)
    try {
      const sig = await signMessageAsync({ message: ZK_KEY_MESSAGE(chainId, deployment.app) })
      const k = await keyFromSeed(hexToBytes(sig))
      rememberKey(k, chainId, deployment.app)
      setKey(k)
      pushLog(`Payment key derived: ${short(k.address, 8)}`, 'ok')
    } catch (e) {
      pushLog(e instanceof Error ? e.message : String(e), 'err')
    } finally {
      setDeriving(false)
    }
  }

  const ctx = useMemo(() => {
    if (!publicClient || !walletClient || !deployment || !key || !address || !token) return null
    return { publicClient, walletClient, deployment, key, account: address as Hex, token }
  }, [publicClient, walletClient, deployment, key, address, token])

  const afterTx = (hash: Hex, what: string) => {
    const explorer = publicClient?.chain?.blockExplorers?.default?.url
    pushLog(`${what} confirmed · ${explorer ? `${explorer}/tx/${hash}` : short(hash, 8)}`, 'ok')
    void doSync()
  }

  return (
    <>
      {testnet && (
        <div className="env-banner" role="status">
          <strong>Test environment</strong>
          You are on {chain?.name ?? `chain ${chainId}`}. Tokens here have no real value.
        </div>
      )}
      <header className="top">
        <div className="brand">
          <h1>Auditable Privacy Payment</h1>
          {chainGroupLabel !== 'default' && <small>{chainGroupLabel}</small>}
          {testnet && <span className="pill warn env-badge">Testnet</span>}
        </div>
        <div className="wallet">
          {isConnected ? (
            <>
              <select
                id="chain"
                className={testnet ? 'testnet' : undefined}
                value={chainId}
                onChange={(e) => switchChain({ chainId: Number(e.target.value) as (typeof chains)[number]['id'] })}
                style={{ width: 'auto' }}
              >
                {chains.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                    {c.testnet ? ' (testnet)' : ''}
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
            connectors
              // EIP-6963 discovery also announces non-EVM wallets (TronLink…); keep EVM wallets only
              .filter((c) => !/tron/i.test(c.name))
              .map((c) => (
                <button key={c.uid} className="primary" disabled={connecting} onClick={() => connect({ connector: c })}>
                  Connect {c.name}
                </button>
              ))
          )}
        </div>
      </header>

      {wrongChain && (
        <section className="card" style={{ marginBottom: 20, borderColor: 'var(--warn)' }}>
          <h2>Wallet is on an unsupported network</h2>
          <p className="hint">
            Your wallet reports chain {walletChainId ?? 'unknown'}. Switch it to {chains.find((c) => c.id === chainId)?.name ?? chainId} to
            continue; the network will be added to the wallet if it is missing.
          </p>
          <div>
            <button className="primary" onClick={() => switchChain({ chainId: chainId as (typeof chains)[number]['id'] })}>
              Switch wallet to {chains.find((c) => c.id === chainId)?.name ?? chainId}
            </button>
          </div>
        </section>
      )}

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
              token={token ?? { symbol: '…', decimals: 18 }}
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
            {(!ctx || !walletRef.current) && (
              <p className="empty">
                {wrongChain
                  ? 'Switch your wallet to the selected network to use this tab.'
                  : !walletClient
                    ? 'Waiting for the wallet client… (approve the connection in your wallet if it is asking)'
                    : !token
                      ? 'Reading token details…'
                      : 'Connecting to the note source…'}
              </p>
            )}
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
