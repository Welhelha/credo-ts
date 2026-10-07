import { randomBytes, randomUUID } from 'node:crypto'
import type { AgentContext } from '@credo-ts/core'
import { Kms, TypedArrayEncoder } from '@credo-ts/core'
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'

const algorithms = {
  'ML-DSA-44': ml_dsa44,
  'ML-DSA-65': ml_dsa65,
  'ML-DSA-87': ml_dsa87,
} as const

type SupportedAlgorithm = keyof typeof algorithms

interface StoredKey {
  alg: SupportedAlgorithm
  seed: Uint8Array
  pub: Uint8Array
}

export class MlDsaNobleKeyManagementService implements Kms.KeyManagementService {
  public readonly backend = 'ml-dsa-noble-spike'

  #keys = new Map<string, StoredKey>()

  private assertSupportedAlgorithm(algorithm: string): asserts algorithm is SupportedAlgorithm {
    if (!(algorithm in algorithms)) {
      throw new Kms.KeyManagementAlgorithmNotSupportedError(`alg '${algorithm}'`, this.backend)
    }
  }

  public isOperationSupported(_agentContext: AgentContext, operation: Kms.KmsOperation): boolean {
    if (operation.operation === 'deleteKey' || operation.operation === 'randomBytes') return true

    if (operation.operation === 'createKey' && operation.type.kty === 'AKP') {
      return operation.type.alg in algorithms
    }

    if (operation.operation === 'importKey' && operation.privateJwk.kty === 'AKP') {
      return operation.privateJwk.alg in algorithms
    }

    if (operation.operation === 'sign' || operation.operation === 'verify') {
      return operation.algorithm in algorithms
    }

    return false
  }

  public randomBytes(_agentContext: AgentContext, options: Kms.KmsRandomBytesOptions): Kms.KmsRandomBytesReturn {
    return randomBytes(options.length)
  }

  public async getPublicKey(_agentContext: AgentContext, keyId: string): Promise<Kms.KmsJwkPublic | null> {
    const stored = this.#keys.get(keyId)
    if (!stored) return null

    return { kid: keyId, kty: 'AKP', alg: stored.alg, pub: TypedArrayEncoder.toBase64Url(stored.pub) }
  }

  public async createKey<Type extends Kms.KmsCreateKeyType>(
    _agentContext: AgentContext,
    options: Kms.KmsCreateKeyOptions<Type>
  ): Promise<Kms.KmsCreateKeyReturn<Type>> {
    if (options.type.kty !== 'AKP') {
      throw new Kms.KeyManagementAlgorithmNotSupportedError(`kty '${String(options.type.kty)}'`, this.backend)
    }
    this.assertSupportedAlgorithm(options.type.alg)

    const algorithm = algorithms[options.type.alg]
    const seed = randomBytes(algorithm.lengths.seed ?? 32)
    const { publicKey } = algorithm.keygen(seed)
    const keyId = options.keyId ?? randomUUID()
    this.#keys.set(keyId, { alg: options.type.alg, seed, pub: publicKey })

    return {
      keyId,
      publicJwk: { kid: keyId, kty: 'AKP', alg: options.type.alg, pub: TypedArrayEncoder.toBase64Url(publicKey) },
    } as unknown as Kms.KmsCreateKeyReturn<Type>
  }

  public async importKey<Jwk extends Kms.KmsJwkPrivate>(
    _agentContext: AgentContext,
    options: Kms.KmsImportKeyOptions<Jwk>
  ): Promise<Kms.KmsImportKeyReturn<Jwk>> {
    const privateJwk = options.privateJwk
    if (privateJwk.kty !== 'AKP') {
      throw new Kms.KeyManagementAlgorithmNotSupportedError(`kty '${String(privateJwk.kty)}'`, this.backend)
    }
    this.assertSupportedAlgorithm(privateJwk.alg)

    const keyId = privateJwk.kid ?? randomUUID()
    const seed = TypedArrayEncoder.fromBase64Url(privateJwk.priv)
    const algorithm = algorithms[privateJwk.alg]
    const { publicKey } = algorithm.keygen(seed)
    const encodedPublicKey = TypedArrayEncoder.toBase64Url(publicKey)
    if (encodedPublicKey !== privateJwk.pub) {
      throw new Kms.KeyManagementError('private seed does not match the provided public key')
    }

    this.#keys.set(keyId, { alg: privateJwk.alg, seed, pub: publicKey })
    return {
      keyId,
      publicJwk: { kid: keyId, kty: 'AKP', alg: privateJwk.alg, pub: encodedPublicKey },
    } as unknown as Kms.KmsImportKeyReturn<Jwk>
  }

  public async deleteKey(_agentContext: AgentContext, options: Kms.KmsDeleteKeyOptions): Promise<boolean> {
    return this.#keys.delete(options.keyId)
  }

  public async sign(_agentContext: AgentContext, options: Kms.KmsSignOptions): Promise<Kms.KmsSignReturn> {
    const stored = this.#keys.get(options.keyId)
    if (!stored) throw new Kms.KeyManagementKeyNotFoundError(options.keyId, [this.backend])
    this.assertSupportedAlgorithm(options.algorithm)
    if (options.algorithm !== stored.alg) {
      throw new Kms.KeyManagementError(
        `key '${options.keyId}' is for algorithm '${stored.alg}' but '${options.algorithm}' was requested`
      )
    }

    const algorithm = algorithms[stored.alg]
    const { secretKey } = algorithm.keygen(stored.seed)
    return { signature: algorithm.sign(options.data, secretKey) }
  }

  public async verify(_agentContext: AgentContext, options: Kms.KmsVerifyOptions): Promise<Kms.KmsVerifyReturn> {
    this.assertSupportedAlgorithm(options.algorithm)

    let publicJwk: Kms.KmsJwkPublicAkp
    if (options.key.keyId) {
      const stored = this.#keys.get(options.key.keyId)
      if (!stored) throw new Kms.KeyManagementKeyNotFoundError(options.key.keyId, [this.backend])
      publicJwk = {
        kid: options.key.keyId,
        kty: 'AKP',
        alg: stored.alg,
        pub: TypedArrayEncoder.toBase64Url(stored.pub),
      }
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

    const publicKey = TypedArrayEncoder.fromBase64Url(publicJwk.pub)
    const verified = algorithms[publicJwk.alg].verify(options.signature, options.data, publicKey)
    return verified ? { verified: true, publicJwk } : { verified: false }
  }

  public async encrypt(_agentContext: AgentContext, _options: Kms.KmsEncryptOptions): Promise<Kms.KmsEncryptReturn> {
    throw new Kms.KeyManagementAlgorithmNotSupportedError('encrypt', this.backend)
  }

  public async decrypt(_agentContext: AgentContext, _options: Kms.KmsDecryptOptions): Promise<Kms.KmsDecryptReturn> {
    throw new Kms.KeyManagementAlgorithmNotSupportedError('decrypt', this.backend)
  }
}
