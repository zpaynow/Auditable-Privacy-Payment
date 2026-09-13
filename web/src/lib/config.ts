import { createConfig, createStorage, http, noopStorage } from 'wagmi'
import { baseSepolia, sepolia } from 'wagmi/chains'
import { defineChain } from 'viem'
import { injected } from 'wagmi/connectors'
import appAbiJson from '../abi/APP.json'
import tokenAbiJson from '../abi/TestToken.json'

export const anvil = defineChain({
  id: 31337,
  name: 'Anvil (local)',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: ['http://127.0.0.1:8545'] } },
  testnet: true,
})

/** BOTChain testnet. */
export const botchainTestnet = defineChain({
  id: 968,
  name: 'BOTChain Testnet',
  nativeCurrency: { name: 'BOT', symbol: 'BOT', decimals: 18 },
  rpcUrls: { default: { http: ['https://rpc.bohr.life'] } },
  blockExplorers: { default: { name: 'BOTChain Explorer', url: 'https://scan.bohr.life' } },
  testnet: true,
})

/** BOTChain mainnet. */
export const botchain = defineChain({
  id: 677,
  name: 'BOTChain',
  nativeCurrency: { name: 'BOT', symbol: 'BOT', decimals: 18 },
  rpcUrls: { default: { http: ['https://rpc.botchain.ai'] } },
  blockExplorers: { default: { name: 'BOTChain Explorer', url: 'https://scan.botchain.ai' } },
})

/** Every chain the app knows how to talk to. Only chains with a deployment file are offered. */
export const registry = [botchain, botchainTestnet, baseSepolia, sepolia, anvil] as const
export type KnownChain = (typeof registry)[number]

/**
 * Hostname → chains. The first label of the hostname (e.g. `botchain` in
 * `botchain.zpaynow.com`) selects a group; `?chains=968,677` overrides for testing; anything
 * else gets the default group. Within a group mainnets are offered before testnets, and the first
 * chain with a deployment is the default.
 */
export const chainGroups: Record<string, number[]> = {
  botchain: [botchain.id, botchainTestnet.id],
  default: [baseSepolia.id, sepolia.id, anvil.id],
}

function selectChainIds(): number[] {
  const params = new URLSearchParams(location.search)
  const override = params.get('chains')
  if (override) return override.split(',').map((x) => Number(x.trim())).filter(Boolean)
  const labels = location.hostname.toLowerCase().split('.')
  for (const label of labels) {
    if (label in chainGroups && label !== 'default') return chainGroups[label]
  }
  return chainGroups.default
}

export interface Deployment {
  chainId: number
  app: `0x${string}`
  token: `0x${string}`
  auditorX: string
  auditorY: string
  auditorAdmin: `0x${string}`
  deployBlock: number
}

// deployments/<chainId>.json written by `forge script script/Deploy.s.sol`
const deploymentFiles = import.meta.glob<Deployment>('../deployments/*.json', { eager: true, import: 'default' })
export const deployments: Record<number, Deployment> = {}
for (const d of Object.values(deploymentFiles)) deployments[Number(d.chainId)] = d

/** The chains offered on this host: the host's group, restricted to chains that have a deployment
 *  (anvil only in dev builds). Falls back to every deployed chain, then to the whole registry.
 *  Mainnets are moved ahead of testnets (stable sort) so the first entry, wagmi's default chain,
 *  is a mainnet whenever the group has one. */
export const selectedChainIds = selectChainIds()
function pickChains(): KnownChain[] {
  const deployed = (id: number) => id in deployments && (import.meta.env.DEV || id !== anvil.id)
  const byId = (id: number) => registry.find((c) => c.id === id)
  let list = selectedChainIds.map(byId).filter((c): c is KnownChain => !!c && deployed(c.id))
  if (list.length === 0) list = registry.filter((c) => deployed(c.id))
  if (list.length === 0) list = [...registry]
  return list.sort((a, b) => Number(!!a.testnet) - Number(!!b.testnet))
}
export const chains = pickChains() as unknown as readonly [KnownChain, ...KnownChain[]]
/** The chain the app starts on (a mainnet whenever the host's group has one). */
export const defaultChain: KnownChain = chains[0]
export const isTestnet = (chainId: number) => !!chains.find((c) => c.id === chainId)?.testnet

/** Human label for the selected group (shown in the header). */
export const chainGroupLabel: string =
  Object.entries(chainGroups).find(([, ids]) => ids.join() === selectedChainIds.join())?.[0] ?? 'custom'

/** wagmi persists the last selected chain in localStorage and would restore it on the next visit.
 *  We keep the persisted connection (so the wallet reconnects) but reset the remembered chain to the
 *  default: every page load starts on the preferred (mainnet) chain, and a testnet is only shown when
 *  the connected wallet is actually on it or the user picks it in the selector. */
function preferDefaultChainStorage() {
  if (typeof localStorage === 'undefined') return noopStorage
  return {
    getItem(key: string) {
      const raw = localStorage.getItem(key)
      if (!raw || key !== 'wagmi.store') return raw
      try {
        const persisted = JSON.parse(raw) as { state?: { chainId?: number } }
        if (persisted.state && typeof persisted.state === 'object') persisted.state.chainId = defaultChain.id
        return JSON.stringify(persisted)
      } catch {
        return raw
      }
    },
    setItem(key: string, value: string) {
      try {
        localStorage.setItem(key, value)
      } catch {
        /* quota / private mode: the app works without persistence */
      }
    },
    removeItem(key: string) {
      localStorage.removeItem(key)
    },
  }
}

export const wagmiConfig = createConfig({
  chains,
  connectors: [injected()],
  storage: createStorage({ storage: preferDefaultChainStorage() }),
  transports: Object.fromEntries(registry.map((c) => [c.id, http(c.rpcUrls.default.http[0])])) as Record<number, ReturnType<typeof http>>,
})

export const appAbi = appAbiJson as unknown as readonly unknown[]
export const tokenAbi = tokenAbiJson as unknown as readonly unknown[]

/** External faucets per chain. When present, the deposit tab links there instead of minting TestToken.
 *  Chains without an entry show the mint button on testnets and a block-explorer token link on mainnets. */
export const faucets: Record<number, string> = {
  [botchainTestnet.id]: 'https://faucet.botchain.ai/en/basic',
}

/** Token metadata read from the registered ERC20 (symbol / decimals). */
export interface TokenMeta {
  symbol: string
  decimals: number
}

/** The only asset registered in Phase 1. */
export const ASSET_ID = 1n

export const TREE_DEPTH = 20
export const MT_PROOF_LEN = TREE_DEPTH * 64 + 32 + 12
export const OWNER_MEMO_LEN = 104
export const AUDIT_MEMO_LEN = 160

export const ZK_KEY_MESSAGE = (chainId: number, app: string) =>
  `Auditable Privacy Payment\n\nSign to derive your private payment key.\nchain: ${chainId}\ncontract: ${app.toLowerCase()}\n\nThis signature never leaves your browser.`
