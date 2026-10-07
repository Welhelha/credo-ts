import { Kms, TypedArrayEncoder } from '@credo-ts/core'
import { getAgentContext } from '../../../../core/tests'
import { NodeInMemoryKeyManagementStorage } from '../NodeInMemoryKeyManagementStorage'
import { NodeKeyManagementService } from '../NodeKeyManagementService'
import { MlDsaNobleKeyManagementService } from './MlDsaNobleKeyManagementService.spike'

const agentContext = getAgentContext({ contextCorrelationId: 'default' })
const algorithms = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const
const message = TypedArrayEncoder.fromUtf8String('Credo ML-DSA backend comparison')
const benchmarkIterations = 1000

type SpikeService = Kms.KeyManagementService

const createNativeService = () => new NodeKeyManagementService(new NodeInMemoryKeyManagementStorage())

const measureAverageMs = async (iterations: number, operation: () => Promise<unknown>) => {
  const startedAt = process.hrtime.bigint()
  for (let iteration = 0; iteration < iterations; iteration++) await operation()
  return Number(process.hrtime.bigint() - startedAt) / 1_000_000 / iterations
}

const createKey = (service: SpikeService, alg: (typeof algorithms)[number]) =>
  service.createKey(agentContext, { type: { kty: 'AKP', alg } })

const sign = (service: SpikeService, keyId: string, alg: (typeof algorithms)[number]) =>
  service.sign(agentContext, { keyId, algorithm: alg, data: message })

const verify = (
  service: SpikeService,
  publicJwk: Kms.KmsJwkPublicAkp,
  alg: (typeof algorithms)[number],
  signature: Uint8Array
) => service.verify(agentContext, { key: { publicJwk }, algorithm: alg, data: message, signature })

describe('ML-DSA noble KMS spike', () => {
  it.each(algorithms)('interoperates with the native Node backend for %s', async (alg) => {
    const nativeService = createNativeService()
    const nobleService = new MlDsaNobleKeyManagementService()
    const nativeKey = await createKey(nativeService, alg)
    const nobleKey = await createKey(nobleService, alg)

    const nativeSignature = await sign(nativeService, nativeKey.keyId, alg)
    const nobleSignature = await sign(nobleService, nobleKey.keyId, alg)

    expect(await verify(nobleService, nativeKey.publicJwk, alg, nativeSignature.signature)).toEqual({
      verified: true,
      publicJwk: nativeKey.publicJwk,
    })
    expect(await verify(nativeService, nobleKey.publicJwk, alg, nobleSignature.signature)).toEqual({
      verified: true,
      publicJwk: nobleKey.publicJwk,
    })
  })

  it('compares Credo KMS operation timings for Node crypto and noble', async () => {
    const rows: Array<Record<string, string | number>> = []

    for (const alg of algorithms) {
      const nativeService = createNativeService()
      const nobleService = new MlDsaNobleKeyManagementService()
      const nativeKey = await createKey(nativeService, alg)
      const nobleKey = await createKey(nobleService, alg)
      const nativeSignature = await sign(nativeService, nativeKey.keyId, alg)
      const nobleSignature = await sign(nobleService, nobleKey.keyId, alg)

      await sign(nativeService, nativeKey.keyId, alg)
      await sign(nobleService, nobleKey.keyId, alg)
      await verify(nativeService, nativeKey.publicJwk, alg, nativeSignature.signature)
      await verify(nobleService, nobleKey.publicJwk, alg, nobleSignature.signature)

      const nodeKeygen = await measureAverageMs(benchmarkIterations, async () => createKey(nativeService, alg))
      const nobleKeygen = await measureAverageMs(benchmarkIterations, async () => createKey(nobleService, alg))
      const nodeSign = await measureAverageMs(benchmarkIterations, async () =>
        sign(nativeService, nativeKey.keyId, alg)
      )
      const nobleSign = await measureAverageMs(benchmarkIterations, async () => sign(nobleService, nobleKey.keyId, alg))
      const nodeVerify = await measureAverageMs(benchmarkIterations, async () =>
        verify(nativeService, nativeKey.publicJwk, alg, nativeSignature.signature)
      )
      const nobleVerify = await measureAverageMs(benchmarkIterations, async () =>
        verify(nobleService, nobleKey.publicJwk, alg, nobleSignature.signature)
      )

      const native = { keygen: nodeKeygen, sign: nodeSign, verify: nodeVerify }
      const noble = { keygen: nobleKeygen, sign: nobleSign, verify: nobleVerify }

      rows.push({
        algorithm: alg,
        iterations: benchmarkIterations,
        'Node keygen ms': Number(native.keygen.toFixed(2)),
        'Noble keygen ms': Number(noble.keygen.toFixed(2)),
        'Node sign ms': Number(native.sign.toFixed(2)),
        'Noble sign ms': Number(noble.sign.toFixed(2)),
        'Node verify ms': Number(native.verify.toFixed(2)),
        'Noble verify ms': Number(noble.verify.toFixed(2)),
      })
    }

    process.stdout.write(
      `${JSON.stringify({ benchmark: 'Credo KMS ML-DSA', unit: 'average milliseconds per operation', rows }, null, 2)}\n`
    )
    expect(rows).toHaveLength(algorithms.length)
  }, 180_000)
})
