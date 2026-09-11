// Development-only injected wallet.
// Open the app with `?devkey=0x<private key>` or `?dev=<anvil account index>` and a minimal EIP-1193
// provider backed by that key is installed as window.ethereum, so the whole flow can be
// exercised without a browser extension. Never use with a key that holds real funds.
import { BaseError, createWalletClient, http, type Hex } from 'viem'
import { mnemonicToAccount, privateKeyToAccount } from 'viem/accounts'
import { anvil } from './config'

export function installDevWallet() {
  const params = new URLSearchParams(location.search)
  const key = params.get('devkey')
  const index = params.get('dev')
  if (!key && index === null) return
  const rpc = params.get('rpc') ?? anvil.rpcUrls.default.http[0]
  const account = key
    ? privateKeyToAccount(key as Hex)
    : mnemonicToAccount('test test test test test test test test test test test junk', { addressIndex: Number(index) })
  const transport = http(rpc)({ chain: anvil })
  const wallet = createWalletClient({ account, chain: anvil, transport: http(rpc) })
  const chainIdHex = `0x${anvil.id.toString(16)}`

  const listeners = new Map<string, Set<(...a: unknown[]) => void>>()
  const provider = {
    isDevWallet: true,
    async request({ method, params }: { method: string; params?: unknown[] }): Promise<unknown> {
      const p = (params ?? []) as never[]
      switch (method) {
        case 'eth_requestAccounts':
        case 'eth_accounts':
          return [account.address]
        case 'eth_chainId':
          return chainIdHex
        case 'wallet_switchEthereumChain':
        case 'wallet_addEthereumChain':
          return null
        case 'personal_sign': {
          const [message] = p as unknown as [Hex]
          return account.signMessage({ message: { raw: message } })
        }
        case 'eth_sendTransaction': {
          const [tx] = p as unknown as [{ to?: Hex; data?: Hex; value?: Hex; gas?: Hex; from?: Hex }]
          try {
            return await wallet.sendTransaction({
              to: tx.to,
              data: tx.data,
              value: tx.value ? BigInt(tx.value) : undefined,
              gas: tx.gas ? BigInt(tx.gas) : undefined,
            })
          } catch (e) {
            // Re-throw as a JSON-RPC error so the outer viem client can decode the revert data.
            const withData = e instanceof BaseError ? (e.walk((x) => typeof (x as { data?: unknown }).data === 'string') as { data?: Hex } | null) : null
            throw { code: 3, message: e instanceof BaseError ? e.shortMessage : String(e), data: withData?.data }
          }
        }
        default:
          return transport.request({ method, params: p } as never)
      }
    },
    on(event: string, cb: (...a: unknown[]) => void) {
      if (!listeners.has(event)) listeners.set(event, new Set())
      listeners.get(event)!.add(cb)
    },
    removeListener(event: string, cb: (...a: unknown[]) => void) {
      listeners.get(event)?.delete(cb)
    },
  }
  ;(window as unknown as { ethereum: unknown }).ethereum = provider
  console.info(`[dev wallet] installed for ${account.address} on ${rpc}`)
}
