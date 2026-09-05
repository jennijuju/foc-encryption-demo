import { Synapse } from '@filoz/synapse-sdk'
import { http } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const RPC_URL = process.env.RPC_URL || 'https://api.calibration.node.glif.io/rpc/v1'

export interface SynapseConfig {
  privateKey: string
  source?: string
}

export function createSynapseClient(config: SynapseConfig): Synapse {
  const privateKey = config.privateKey.startsWith('0x')
    ? (config.privateKey as `0x${string}`)
    : (`0x${config.privateKey}` as `0x${string}`)
  const account = privateKeyToAccount(privateKey)
  return Synapse.create({
    account,
    transport: http(RPC_URL),
    source: config.source ?? 'foc-demo',
  })
}
