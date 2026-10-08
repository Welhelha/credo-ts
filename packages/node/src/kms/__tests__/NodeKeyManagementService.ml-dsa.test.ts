import { Kms } from '@credo-ts/core'
import { getAgentContext } from '../../../../core/tests'
import { NodeInMemoryKeyManagementStorage } from '../NodeInMemoryKeyManagementStorage'
import { NodeKeyManagementService } from '../NodeKeyManagementService'

const agentContext = getAgentContext({ contextCorrelationId: 'default' })

const mlDsaAlgs = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const

describe('NodeKeyManagementService ML-DSA (AKP)', () => {
  let service: NodeKeyManagementService
  let storage: NodeInMemoryKeyManagementStorage

  beforeEach(() => {
    storage = new NodeInMemoryKeyManagementStorage()
    service = new NodeKeyManagementService(storage)
  })

  describe('createKey', () => {
    it.each(mlDsaAlgs)('creates AKP %s key successfully', async (alg) => {
      const result = await service.createKey(agentContext, {
        type: { kty: 'AKP', alg },
      })

      const publicJwk = await service.getPublicKey(agentContext, result.keyId)
      expect(result.publicJwk).toEqual(publicJwk)

      expect(result).toEqual({
        keyId: result.keyId,
        publicJwk: {
          kty: 'AKP',
          alg,
          pub: expect.any(String),
          kid: result.keyId,
        },
      })

      // Public JWK should not contain private key material
      expect(publicJwk).not.toHaveProperty('priv')
    })

    it('throws error for unsupported AKP alg', async () => {
      await expect(
        service.createKey(agentContext, {
          // @ts-expect-error Testing invalid type
          type: { kty: 'AKP', alg: 'ML-DSA-999' },
        })
      ).rejects.toThrow(new Kms.KeyManagementAlgorithmNotSupportedError(`alg 'ML-DSA-999' for kty 'AKP'`, 'node'))
    })
  })

  describe('sign and verify', () => {
    it.each(mlDsaAlgs)('signs and verifies with %s', async (alg) => {
      const { keyId, publicJwk } = await service.createKey(agentContext, {
        type: { kty: 'AKP', alg },
      })

      const data = new Uint8Array([1, 2, 3])
      const { signature } = await service.sign(agentContext, {
        keyId,
        algorithm: alg,
        data,
      })

      expect(signature).toEqual(expect.any(Uint8Array))
      expect(signature.length).toBeGreaterThan(0)

      const result = await service.verify(agentContext, {
        key: { publicJwk },
        algorithm: alg,
        data,
        signature,
      })

      expect(result).toEqual({ verified: true, publicJwk })
    })

    it('returns false for modified data with ML-DSA-44', async () => {
      const { keyId } = await service.createKey(agentContext, {
        type: { kty: 'AKP', alg: 'ML-DSA-44' },
      })

      const data = new Uint8Array([1, 2, 3])
      const { signature } = await service.sign(agentContext, {
        keyId,
        algorithm: 'ML-DSA-44',
        data,
      })

      const modifiedData = new Uint8Array([1, 2, 4])
      const result = await service.verify(agentContext, {
        key: { keyId },
        algorithm: 'ML-DSA-44',
        data: modifiedData,
        signature,
      })

      expect(result).toEqual({ verified: false })
    })

    it('returns false for tampered signature with ML-DSA-44', async () => {
      const { keyId } = await service.createKey(agentContext, {
        type: { kty: 'AKP', alg: 'ML-DSA-44' },
      })

      const data = new Uint8Array([1, 2, 3])
      const { signature } = await service.sign(agentContext, {
        keyId,
        algorithm: 'ML-DSA-44',
        data,
      })

      const tamperedSignature = new Uint8Array(signature.length)
      signature.forEach((byte, i) => {
        tamperedSignature[i] = byte ^ 0xff
      })

      const result = await service.verify(agentContext, {
        key: { keyId },
        algorithm: 'ML-DSA-44',
        data,
        signature: tamperedSignature,
      })

      expect(result).toEqual({ verified: false })
    })

    it('rejects wrong algorithm for ML-DSA key', async () => {
      const { keyId } = await service.createKey(agentContext, {
        type: { kty: 'AKP', alg: 'ML-DSA-44' },
      })

      await expect(
        service.sign(agentContext, {
          keyId,
          algorithm: 'EdDSA',
          data: new Uint8Array([1, 2, 3]),
        })
      ).rejects.toThrow(Kms.KeyManagementError)
    })
  })

  describe('importKey', () => {
    it('imports an AKP ML-DSA-44 key pair and can sign/verify with it', async () => {
      // Create a key, get the private jwk, delete it, and re-import it
      const { keyId } = await service.createKey(agentContext, {
        type: { kty: 'AKP', alg: 'ML-DSA-44' },
      })

      const storedPrivateJwk = await storage.get(agentContext, keyId)
      expect(storedPrivateJwk).not.toBeNull()
      expect(storedPrivateJwk?.kty).toBe('AKP')

      await service.deleteKey(agentContext, { keyId })
      expect(await service.getPublicKey(agentContext, keyId)).toBeNull()

      const imported = await service.importKey(agentContext, {
        privateJwk: storedPrivateJwk as Kms.KmsJwkPrivateAkp,
      })

      expect(imported.keyId).toBe(keyId)

      const data = new Uint8Array([1, 2, 3])
      const { signature } = await service.sign(agentContext, {
        keyId,
        algorithm: 'ML-DSA-44',
        data,
      })

      const result = await service.verify(agentContext, {
        key: { keyId },
        algorithm: 'ML-DSA-44',
        data,
        signature,
      })

      expect(result).toEqual({ verified: true, publicJwk: imported.publicJwk })
    })
  })

  describe('isOperationSupported', () => {
    it('supports creating AKP ML-DSA keys', () => {
      for (const alg of mlDsaAlgs) {
        expect(
          service.isOperationSupported(agentContext, {
            operation: 'createKey',
            type: { kty: 'AKP', alg },
          })
        ).toBe(true)
      }
    })

    it('supports signing with ML-DSA algorithms', () => {
      for (const alg of mlDsaAlgs) {
        expect(
          service.isOperationSupported(agentContext, {
            operation: 'sign',
            algorithm: alg,
          })
        ).toBe(true)
      }
    })
  })

  describe('determinism from seed', () => {
    it('derives the same public key from the same seed (priv component)', async () => {
      const { generateKeyPairSync, createPrivateKey } = await import('node:crypto')

      const { privateKey } = generateKeyPairSync('ml-dsa-44')
      const privateJwk = privateKey.export({ format: 'jwk' }) as Kms.KmsJwkPrivateAkp

      // The JWK `priv` component of ML-DSA is the seed. Re-deriving a key from
      // the same seed must result in the same public key.
      const reDerived = createPrivateKey({
        format: 'jwk',
        key: { kty: 'AKP', alg: 'ML-DSA-44', priv: privateJwk.priv, pub: privateJwk.pub },
      })

      const reDerivedJwk = reDerived.export({ format: 'jwk' }) as Kms.KmsJwkPublicAkp
      expect(reDerivedJwk.pub).toBe(privateJwk.pub)
    })
  })
})
