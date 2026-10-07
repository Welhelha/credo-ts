import type { AgentContext } from '@credo-ts/core'
import {
  ClaimFormat,
  DidDocumentBuilder,
  DidResolverService,
  DidsApi,
  JwsService,
  Kms,
  W3cV2Credential,
  W3cV2JwtCredentialService,
  X509ModuleConfig,
} from '@credo-ts/core'
import { getAgentContext } from '../../../../core/tests'
import { NodeInMemoryKeyManagementStorage } from '../NodeInMemoryKeyManagementStorage'
import { NodeKeyManagementService } from '../NodeKeyManagementService'
import { MlDsaNobleKeyManagementService } from './MlDsaNobleKeyManagementService.spike'

const algorithms = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const
const iterations = 100
const warmupIterations = 10

const issuerDid = 'did:example:mldsa-issuer'
const verificationMethodId = `${issuerDid}#ml-dsa-key`

type Stats = { avg: number; median: number }

const computeStats = (samples: number[]): Stats => {
  const sorted = [...samples].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  const median = sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid]
  const avg = samples.reduce((sum, value) => sum + value, 0) / samples.length
  return { avg, median }
}

const measureStats = async (count: number, warmup: number, operation: () => Promise<unknown>): Promise<Stats> => {
  for (let index = 0; index < warmup; index++) await operation()

  const samples: number[] = []
  for (let index = 0; index < count; index++) {
    const startedAt = process.hrtime.bigint()
    await operation()
    samples.push(Number(process.hrtime.bigint() - startedAt) / 1_000_000)
  }
  return computeStats(samples)
}

const round = (value: number) => Number(value.toFixed(2))

const createCredential = () =>
  new W3cV2Credential({
    type: ['VerifiableCredential', 'PerformanceTestCredential'],
    issuer: issuerDid,
    validFrom: new Date().toISOString(),
    credentialSubject: {
      id: 'did:example:holder',
      name: 'Benchmark Subject',
      degree: { type: 'BachelorDegree', name: 'Computer Science' },
    },
  })

const createBackend = (backend: 'node' | 'noble'): Kms.KeyManagementService =>
  backend === 'node'
    ? new NodeKeyManagementService(new NodeInMemoryKeyManagementStorage())
    : new MlDsaNobleKeyManagementService()

const createBenchmarkContext = async (
  backend: 'node' | 'noble',
  alg: (typeof algorithms)[number]
): Promise<{ agentContext: AgentContext; credentialService: W3cV2JwtCredentialService }> => {
  const keyManagementService = createBackend(backend)
  const agentContext = getAgentContext({
    kmsBackends: [keyManagementService],
    registerInstances: [[X509ModuleConfig, new X509ModuleConfig()]],
  })
  const kms = agentContext.resolve(Kms.KeyManagementApi)
  const { keyId, publicJwk } = await kms.createKey({ type: { kty: 'AKP', alg } })

  const didDocument = new DidDocumentBuilder(issuerDid)
    .addContext('https://w3id.org/security/jws/v1')
    .addVerificationMethod({
      id: verificationMethodId,
      type: 'JsonWebKey2020',
      controller: issuerDid,
      publicKeyJwk: publicJwk,
    })
    .addAssertionMethod(verificationMethodId)
    .build()

  agentContext.dependencyManager.registerInstance(DidsApi, {
    resolveCreatedDidDocumentWithKeys: async () => ({
      didDocument,
      keys: [{ didDocumentRelativeKeyId: '#ml-dsa-key', kmsKeyId: keyId }],
    }),
  } as unknown as DidsApi)
  agentContext.dependencyManager.registerInstance(DidResolverService, {
    resolveDidDocument: async () => didDocument,
  } as unknown as DidResolverService)

  return {
    agentContext,
    credentialService: new W3cV2JwtCredentialService(new JwsService()),
  }
}

describe('ML-DSA VC-JWT performance spike', () => {
  it.each(algorithms)('issues and verifies VC-JWT using Node and Noble for %s', async (alg) => {
    const native = await createBenchmarkContext('node', alg)
    const noble = await createBenchmarkContext('noble', alg)
    const credential = createCredential()

    const nodeVc = await native.credentialService.signCredential(native.agentContext, {
      alg,
      format: ClaimFormat.JwtW3cVc,
      verificationMethod: verificationMethodId,
      credential,
    })
    const nobleVc = await noble.credentialService.signCredential(noble.agentContext, {
      alg,
      format: ClaimFormat.JwtW3cVc,
      verificationMethod: verificationMethodId,
      credential,
    })

    const nativeVerification = await native.credentialService.verifyCredential(native.agentContext, {
      credential: nodeVc,
    })
    expect(nativeVerification).toMatchObject({ isValid: true })
    const nobleVerification = await noble.credentialService.verifyCredential(noble.agentContext, {
      credential: nobleVc,
    })
    expect(nobleVerification).toMatchObject({ isValid: true })
    const nativeSignatureOnNoble = await noble.credentialService.verifyCredential(native.agentContext, {
      credential: nodeVc.encoded,
    })
    const nobleSignatureOnNative = await native.credentialService.verifyCredential(noble.agentContext, {
      credential: nobleVc.encoded,
    })
    expect(nativeSignatureOnNoble.validations.signature?.isValid).toBe(true)
    expect(nobleSignatureOnNative.validations.signature?.isValid).toBe(true)
  })

  it('benchmarks VC-JWT issuance and verification including Credo validation and JWS processing', async () => {
    const results: Array<Record<string, string | number>> = []

    for (const alg of algorithms) {
      const node = await createBenchmarkContext('node', alg)
      const noble = await createBenchmarkContext('noble', alg)
      const nodeVc = await node.credentialService.signCredential(node.agentContext, {
        alg,
        format: ClaimFormat.JwtW3cVc,
        verificationMethod: verificationMethodId,
        credential: createCredential(),
      })
      const nobleVc = await noble.credentialService.signCredential(noble.agentContext, {
        alg,
        format: ClaimFormat.JwtW3cVc,
        verificationMethod: verificationMethodId,
        credential: createCredential(),
      })

      const nodeSign = await measureStats(iterations, warmupIterations, async () =>
        node.credentialService.signCredential(node.agentContext, {
          alg,
          format: ClaimFormat.JwtW3cVc,
          verificationMethod: verificationMethodId,
          credential: createCredential(),
        })
      )
      const nobleSign = await measureStats(iterations, warmupIterations, async () =>
        noble.credentialService.signCredential(noble.agentContext, {
          alg,
          format: ClaimFormat.JwtW3cVc,
          verificationMethod: verificationMethodId,
          credential: createCredential(),
        })
      )
      const nodeVerify = await measureStats(iterations, warmupIterations, async () =>
        node.credentialService.verifyCredential(node.agentContext, { credential: nodeVc })
      )
      const nobleVerify = await measureStats(iterations, warmupIterations, async () =>
        noble.credentialService.verifyCredential(noble.agentContext, { credential: nobleVc })
      )

      results.push({
        algorithm: alg,
        iterations,
        warmupIterations,
        'Node issuance median (avg) ms': round(nodeSign.median) + ' (' + round(nodeSign.avg) + ')',
        'Noble issuance median (avg) ms': round(nobleSign.median) + ' (' + round(nobleSign.avg) + ')',
        'Node verification median (avg) ms': round(nodeVerify.median) + ' (' + round(nodeVerify.avg) + ')',
        'Noble verification median (avg) ms': round(nobleVerify.median) + ' (' + round(nobleVerify.avg) + ')',
        'VC-JWT bytes': nodeVc.encoded.length,
      })
    }

    process.stdout.write(
      `${JSON.stringify(
        {
          benchmark: 'Credo VC-JWT ML-DSA',
          unit: 'milliseconds per VC (average and median)',
          iterations,
          warmupIterations,
          results,
        },
        null,
        2
      )}\n`
    )
    expect(results).toHaveLength(algorithms.length)
  }, 600_000)
})