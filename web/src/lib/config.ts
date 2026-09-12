import { createConfig, http } from 'wagmi'
import { baseSepolia } from 'wagmi/chains'
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

/** BOTChain testnet — the default network. */
export const botchainTestnet = defineChain({
  id: 968,
  name: 'BOTChain Testnet',
  nativeCurrency: { name: 'BOT', symbol: 'BOT', decimals: 18 },
  rpcUrls: { default: { http: ['https://rpc.bohr.life'] } },
  blockExplorers: { default: { name: 'BOTChain Explorer', url: 'https://scan.bohr.life' } },
  testnet: true,
})

// first entry is the default; the local anvil chain is only offered in dev builds
export const chains = (import.meta.env.DEV ? [botchainTestnet, baseSepolia, anvil] : [botchainTestnet, baseSepolia]) as unknown as readonly [
  typeof botchainTestnet,
  ...(typeof baseSepolia | typeof anvil)[],
]

export const wagmiConfig = createConfig({
  chains,
  connectors: [injected()],
  transports: {
    [botchainTestnet.id]: http('https://rpc.bohr.life'),
    [baseSepolia.id]: http(),
    [anvil.id]: http('http://127.0.0.1:8545'),
  },
})

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

export const appAbi = appAbiJson as unknown as readonly unknown[]
export const tokenAbi = tokenAbiJson as unknown as readonly unknown[]

/** External faucets per chain. When present, the deposit tab links there instead of minting TestToken. */
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
