/**
 * Spike: minimal Credo KeyManagementService storing an ML-DSA seed and
 * signing with native Node ML-DSA.
 *
 * The service only stores the 32-byte ML-DSA seed (the JWK `priv` component)
 * as secret key material, plus the derived public key. At signing time the
 * private key is reconstructed from the seed using the native Node crypto
 * implementation and a signature is produced with `crypto.sign(null, ...)`.
 *
 * This is a spike: no encryption/decryption, no key agreement, ML-DSA only.
 */
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  randomBytes,
  randomUUID,
} from 'node:crypto'
import { promisify } from 'node:util'
import type { AgentContext } from '@credo-ts/core'
import { Kms, TypedArrayEncoder } from '@credo-ts/core'
import { getAgentContext } from '../../../../core/tests'

const nodeSignPromisified = promisify(nodeSign)
const nodeVerifyPromisified = promisify(nodeVerify)

const supportedAlgs = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const
type SupportedAlg = (typeof supportedAlgs)[number]

const algToNodeAlgorithm = {
  'ML-DSA-44': 'ml-dsa-44',
  'ML-DSA-65': 'ml-dsa-65',
  'ML-DSA-87': 'ml-dsa-87',
} as const satisfies Record<SupportedAlg, 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87'>

/**
 * The only secret material we persist: the seed and the public key.
 */
interface StoredMlDsaSeed {
  alg: SupportedAlg
  seed: Uint8Array
  pub: string
}

export class MlDsaSeedKeyManagementService implements Kms.KeyManagementService {
  public readonly backend = 'ml-dsa-seed-spike'

  #seeds = new Map<string, StoredMlDsaSeed>()

  private assertSupportedAlg(alg: string): asserts alg is SupportedAlg {
    if (!supportedAlgs.includes(alg as SupportedAlg)) {
      throw new Kms.KeyManagementAlgorithmNotSupportedError(`alg '${alg}'`, this.backend)
    }
  }

  public isOperationSupported(_agentContext: AgentContext, operation: Kms.KmsOperation): boolean {
    if (operation.operation === 'deleteKey') return true
    if (operation.operation === 'randomBytes') return true

    if (operation.operation === 'createKey' && operation.type.kty === 'AKP') {
      return supportedAlgs.includes(operation.type.alg as SupportedAlg)
    }

    if (operation.operation === 'importKey' && operation.privateJwk.kty === 'AKP') {
      return supportedAlgs.includes(operation.privateJwk.alg as SupportedAlg)
    }

    if (operation.operation === 'sign' || operation.operation === 'verify') {
      return supportedAlgs.includes(operation.algorithm as SupportedAlg)
    }

    return false
  }

  public randomBytes(_agentContext: AgentContext, options: Kms.KmsRandomBytesOptions): Kms.KmsRandomBytesReturn {
    return randomBytes(options.length)
  }

  public async getPublicKey(_agentContext: AgentContext, keyId: string): Promise<Kms.KmsJwkPublic | null> {
    const stored = this.#seeds.get(keyId)
    if (!stored) return null

    return {
      kid: keyId,
      kty: 'AKP',
      alg: stored.alg,
      pub: stored.pub,
    }
  }

  public async createKey<Type extends Kms.KmsCreateKeyType>(
    _agentContext: AgentContext,
    options: Kms.KmsCreateKeyOptions<Type>
  ): Promise<Kms.KmsCreateKeyReturn<Type>> {
    const { type, keyId } = options

    if (type.kty !== 'AKP') {
      throw new Kms.KeyManagementAlgorithmNotSupportedError(`kty '${type.kty}'`, this.backend)
    }
    this.assertSupportedAlg(type.alg)

    const { publicKey, privateKey } = generateKeyPairSync(algToNodeAlgorithm[type.alg])
    const privateJwk = privateKey.export({ format: 'jwk' }) as { priv: string }
    const publicJwk = publicKey.export({ format: 'jwk' }) as { pub: string }

    const kid = keyId ?? randomUUID()
    // Only the seed (priv) + public key are stored
    this.#seeds.set(kid, {
      alg: type.alg,
      seed: TypedArrayEncoder.fromBase64Url(privateJwk.priv),
      pub: publicJwk.pub,
    })

    return {
      keyId: kid,
      publicJwk: { kid, kty: 'AKP', alg: type.alg, pub: publicJwk.pub },
    }as unknown as Kms.KmsCreateKeyReturn<Type>
  }

  public async importKey<Jwk extends Kms.KmsJwkPrivate>(
    _agentContext: AgentContext,
    options: Kms.KmsImportKeyOptions<Jwk>
  ): Promise<Kms.KmsImportKeyReturn<Jwk>> {
    const privateJwk = options.privateJwk

    if (privateJwk.kty !== 'AKP') {
      throw new Kms.KeyManagementAlgorithmNotSupportedError(`kty '${privateJwk.kty}'`, this.backend)
    }
    this.assertSupportedAlg(privateJwk.alg)

    const kid = privateJwk.kid ?? randomUUID()
    this.#seeds.set(kid, {
      alg: privateJwk.alg,
      seed: TypedArrayEncoder.fromBase64Url(privateJwk.priv),
      pub: privateJwk.pub,
    })

    return {
      keyId: kid,
      publicJwk: { kid, kty: 'AKP', alg: privateJwk.alg, pub: privateJwk.pub },
    } as unknown as Kms.KmsImportKeyReturn<Jwk>
  }

  public async deleteKey(_agentContext: AgentContext, options: Kms.KmsDeleteKeyOptions): Promise<boolean> {
    return this.#seeds.delete(options.keyId)
  }

  /**
   * Spike-only introspection: returns the stored seed for a key.
   */
  public getStoredSeed(keyId: string): Uint8Array | undefined {
    return this.#seeds.get(keyId)?.seed
  }

  /**
   * Reconstruct the native private key from the stored seed. This is the core
   * of the spike: everything else (pub, alg) is public data, the seed is the
   * only secret we keep in memory.
   */
  private privateKeyFromSeed(stored: StoredMlDsaSeed) {
    return createPrivateKey({
      format: 'jwk',
      key: {
        kty: 'AKP',
        alg: stored.alg,
        priv: TypedArrayEncoder.toBase64Url(stored.seed),
        pub: stored.pub,
      },
    })
  }

  public async sign(_agentContext: AgentContext, options: Kms.KmsSignOptions): Promise<Kms.KmsSignReturn> {
    const stored = this.#seeds.get(options.keyId)
    if (!stored) throw new Kms.KeyManagementKeyNotFoundError(options.keyId, [this.backend])

    this.assertSupportedAlg(options.algorithm)
    if (options.algorithm !== stored.alg) {
      throw new Kms.KeyManagementError(
        `key '${options.keyId}' is for algorithm '${stored.alg}' but '${options.algorithm}' was requested`
      )
    }

    const privateKey = this.privateKeyFromSeed(stored)
    const signature = await nodeSignPromisified(null, options.data, privateKey)

    return { signature: new Uint8Array(signature) }
  }

  public async verify(_agentContext: AgentContext, options: Kms.KmsVerifyOptions): Promise<Kms.KmsVerifyReturn> {
    this.assertSupportedAlg(options.algorithm)

    let publicJwk: Kms.KmsJwkPublicAkp
    if (options.key.keyId) {
      const stored = this.#seeds.get(options.key.keyId)
      if (!stored) throw new Kms.KeyManagementKeyNotFoundError(options.key.keyId, [this.backend])

      publicJwk = { kid: options.key.keyId, kty: 'AKP', alg: stored.alg, pub: stored.pub }
    } else if (options.key.publicJwk?.kty === 'AKP') {
      publicJwk = options.key.publicJwk
    } else {
      throw new Kms.KeyManagementAlgorithmNotSupportedError(`kty '${options.key.publicJwk?.kty}'`, this.backend)
    }

    if (options.algorithm !== publicJwk.alg) {
      throw new Kms.KeyManagementError(
        `key is for algorithm '${publicJwk.alg}' but '${options.algorithm}' was requested`
      )
    }

    const publicKey = createPublicKey({
      format: 'jwk',
      key: { kty: 'AKP', alg: publicJwk.alg, pub: publicJwk.pub },
    })

    const verified = await nodeVerifyPromisified(null, options.data, publicKey, options.signature)

    return verified ? { verified: true, publicJwk } : { verified: false }
  }

  public async encrypt(_agentContext: AgentContext, _options: Kms.KmsEncryptOptions): Promise<Kms.KmsEncryptReturn> {
    throw new Kms.KeyManagementAlgorithmNotSupportedError('encrypt', this.backend)
  }

  public async decrypt(_agentContext: AgentContext, _options: Kms.KmsDecryptOptions): Promise<Kms.KmsDecryptReturn> {
    throw new Kms.KeyManagementAlgorithmNotSupportedError('decrypt', this.backend)
  }
}

const agentContext = getAgentContext({ contextCorrelationId: 'default' })

describe('MlDsaSeedKeyManagementService (spike)', () => {
  let service: MlDsaSeedKeyManagementService

  beforeEach(() => {
    service = new MlDsaSeedKeyManagementService()
  })

  it('stores only the seed as secret material', async () => {
    const { keyId, publicJwk } = await service.createKey(agentContext, {
      type: { kty: 'AKP', alg: 'ML-DSA-44' },
    })

    expect(publicJwk).toEqual({
      kid: keyId,
      kty: 'AKP',
      alg: 'ML-DSA-44',
      pub: expect.any(String),
    })

    // Only the seed is stored, exactly 32 bytes as per FIPS 204
    const storedSeed = service.getStoredSeed(keyId)
    expect(storedSeed).toEqual(expect.any(Uint8Array))
    expect(storedSeed?.length).toBe(32)

    expect(await service.getPublicKey(agentContext, keyId)).toEqual(publicJwk)
  })

  it('signs and verifies with native Node ML-DSA reconstructed from the seed', async () => {
    const { keyId, publicJwk } = await service.createKey(agentContext, {
      type: { kty: 'AKP', alg: 'ML-DSA-65' },
    })

    const data = TypedArrayEncoder.fromUtf8String('signing with the seed')

    const { signature } = await service.sign(agentContext, { keyId, algorithm: 'ML-DSA-65', data })
    expect(signature).toEqual(expect.any(Uint8Array))

    // Native node check: the signature is a valid ML-DSA-65 signature
    const publicKey = createPublicKey({
      format: 'jwk',
      key: { kty: 'AKP', alg: 'ML-DSA-65', pub: publicJwk.pub },
    })
    expect(await nodeVerifyPromisified(null, data, publicKey, signature)).toBe(true)

    // Service verify via keyId
    expect(await service.verify(agentContext, { key: { keyId }, algorithm: 'ML-DSA-65', data, signature })).toEqual({
      verified: true,
      publicJwk,
    })

    // Service verify via publicJwk only (no stored key needed)
    expect(await service.verify(agentContext, { key: { publicJwk }, algorithm: 'ML-DSA-65', data, signature })).toEqual(
      { verified: true, publicJwk }
    )

    // Tampered data fails
    expect(
      await service.verify(agentContext, {
        key: { keyId },
        algorithm: 'ML-DSA-65',
        data: TypedArrayEncoder.fromUtf8String('tampered'),
        signature,
      })
    ).toEqual({ verified: false })
  })

  it('rejects signing with the wrong algorithm', async () => {
    const { keyId } = await service.createKey(agentContext, {
      type: { kty: 'AKP', alg: 'ML-DSA-44' },
    })

    await expect(
      service.sign(agentContext, {
        keyId,
        algorithm: 'ML-DSA-65',
        data: new Uint8Array([1, 2, 3]),
      })
    ).rejects.toThrow(Kms.KeyManagementError)
  })

  it('produces identical signatures when the key is recreated from the same seed', async () => {
    const { keyId, publicJwk } = await service.createKey(agentContext, {
      type: { kty: 'AKP', alg: 'ML-DSA-44' },
    })

    const storedSeed = service.getStoredSeed(keyId)
    expect(storedSeed).toBeDefined()

    const seedJwk = {
      kid: keyId,
      kty: 'AKP',
      alg: 'ML-DSA-44',
      pub: publicJwk.pub,
      priv: TypedArrayEncoder.toBase64Url(storedSeed as Uint8Array),
    }

    // Delete the key and re-import it from the seed: the reconstructed key
    // must verify signatures made by the original key
    await service.deleteKey(agentContext, { keyId })
    const imported = await service.importKey(agentContext, { privateJwk: seedJwk as Kms.KmsJwkPrivateAkp })

    const data = new Uint8Array([9, 8, 7])
    const { signature } = await service.sign(agentContext, {
      keyId: imported.keyId,
      algorithm: 'ML-DSA-44',
      data,
    })

    expect(await service.verify(agentContext, { key: { keyId }, algorithm: 'ML-DSA-44', data, signature })).toEqual({
      verified: true,
      publicJwk: imported.publicJwk,
    })
  })

  it('isOperationSupported reports support only for ML-DSA operations', () => {
    expect(
      service.isOperationSupported(agentContext, {
        operation: 'createKey',
        type: { kty: 'AKP', alg: 'ML-DSA-44' },
      })
    ).toBe(true)
    expect(
      service.isOperationSupported(agentContext, {
        operation: 'createKey',
        type: { kty: 'EC', crv: 'P-256' },
      })
    ).toBe(false)
    expect(
      service.isOperationSupported(agentContext, {
        operation: 'sign',
        algorithm: 'ML-DSA-87',
      })
    ).toBe(true)
    expect(
      service.isOperationSupported(agentContext, {
        operation: 'encrypt',
        encryption: { algorithm: 'A256GCM', iv: new Uint8Array(12) },
      })
    ).toBe(false)
  })
})
