import {
  verify as _verify,
  constants,
  createHmac,
  createPublicKey,
  createSecretKey,
  timingSafeEqual,
} from 'node:crypto'
import { promisify } from 'node:util'
import { type CanBePromise, Kms, TypedArrayEncoder } from '@credo-ts/core'
import { getMlDsa } from './createKey'
import { mapJwaSignatureAlgorithmToNode } from './sign'

const verify = promisify(_verify)

export function performVerify(
  key: Kms.KmsJwkPrivate | Kms.KmsJwkPublicEc | Kms.KmsJwkPublicOkp | Kms.KmsJwkPublicRsa | Kms.KmsJwkPublicAkp,
  algorithm: Kms.KnownJwaSignatureAlgorithm,
  data: Uint8Array,
  signature: Uint8Array
): CanBePromise<boolean> {
  if (key.kty === 'AKP') {
    if (key.alg !== algorithm) {
      throw new Kms.KeyManagementError(`AKP key with alg '${key.alg}' cannot be used with algorithm '${algorithm}'`)
    }

    return getMlDsa(key.alg).verify(signature, data, TypedArrayEncoder.fromBase64Url(key.pub))
  }

  const nodeAlgorithm = mapJwaSignatureAlgorithmToNode(algorithm)
  const nodeKey =
    key.kty === 'oct'
      ? createSecretKey(TypedArrayEncoder.fromBase64Url(key.k))
      : createPublicKey({ format: 'jwk', key })

  switch (key.kty) {
    case 'RSA':
    case 'OKP': {
      const nodeKeyInput = algorithm.startsWith('PS')
        ? // For RSA-PSS, we need to set padding
          {
            key: nodeKey,
            padding: constants.RSA_PKCS1_PSS_PADDING,
            saltLength: Number.parseInt(algorithm.slice(2), 10) / 8,
          }
        : nodeKey

      return verify(nodeAlgorithm, data, nodeKeyInput, signature)
    }
    case 'EC': {
      // Node expects DER encoded signature, but we input raw
      return verify(nodeAlgorithm, data, nodeKey, Kms.rawEcSignatureToDer(signature, key.crv))
    }
    case 'oct': {
      const expectedHmac = createHmac(nodeAlgorithm as string, nodeKey)
        .update(data)
        .digest()

      return timingSafeEqual(expectedHmac, signature)
    }
    default:
      // @ts-expect-error
      throw new Kms.KeyManagementAlgorithmNotSupportedError(`kty '${key.kty}'`, 'node')
  }
}
