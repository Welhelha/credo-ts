import { generateKeyPair as _generateKeyPair, randomBytes } from 'node:crypto'
import { promisify } from 'node:util'
import { Kms, TypedArrayEncoder } from '@credo-ts/core'
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'

const generateKeyPair = promisify(_generateKeyPair)

const nodeSupportedEcCrvs = ['P-256', 'P-384', 'P-521', 'secp256k1'] satisfies Kms.KmsJwkPublicEc['crv'][]
export type NodeKmsSupportedEcCrvs = (typeof nodeSupportedEcCrvs)[number]
export function assertNodeSupportedEcCrv(
  options: Kms.KmsCreateKeyTypeEc
): asserts options is Kms.KmsCreateKeyTypeEc & { crv: NodeKmsSupportedEcCrvs } {
  if (!nodeSupportedEcCrvs.includes(options.crv as NodeKmsSupportedEcCrvs)) {
    throw new Kms.KeyManagementAlgorithmNotSupportedError(`crv '${options.crv}' for kty '${options.kty}'`, 'node')
  }
}

export async function createEcKey({ crv }: Kms.KmsCreateKeyTypeEc & { crv: NodeKmsSupportedEcCrvs }) {
  const { publicKey, privateKey } = await generateKeyPair('ec', {
    namedCurve: crv,
  })

  const privateJwk = privateKey.export({
    format: 'jwk',
  })

  const publicJwk = publicKey.export({
    format: 'jwk',
  })

  return {
    privateJwk: privateJwk as Kms.KmsJwkPrivateEc,
    publicJwk: publicJwk as Kms.KmsJwkPublicEc,
  }
}

export async function createRsaKey({ modulusLength }: Kms.KmsCreateKeyTypeRsa) {
  const { publicKey, privateKey } = await generateKeyPair('rsa', {
    modulusLength,
  })

  const privateJwk = privateKey.export({
    format: 'jwk',
  })

  const publicJwk = publicKey.export({
    format: 'jwk',
  })

  return {
    privateJwk: privateJwk as Kms.KmsJwkPrivateRsa,
    publicJwk: publicJwk as Kms.KmsJwkPublicRsa,
  }
}

const nodeSupportedOkpCrvs = ['Ed25519', 'X25519'] satisfies Kms.KmsJwkPublicOkp['crv'][]
type NodeKmsSupportedOkpCrvs = (typeof nodeSupportedOkpCrvs)[number]
export function assertNodeSupportedOkpCrv(
  options: Kms.KmsCreateKeyTypeOkp
): asserts options is Kms.KmsCreateKeyTypeOkp & { crv: NodeKmsSupportedOkpCrvs } {
  if (!nodeSupportedOkpCrvs.includes(options.crv as NodeKmsSupportedOkpCrvs)) {
    throw new Kms.KeyManagementAlgorithmNotSupportedError(`crv '${options.crv}' for kty '${options.kty}'`, 'node')
  }
}

export async function createOkpKey({ crv }: Kms.KmsCreateKeyTypeOkp & { crv: NodeKmsSupportedOkpCrvs }) {
  const { publicKey, privateKey } =
    crv === 'Ed25519' ? await generateKeyPair('ed25519') : await generateKeyPair('x25519')

  const privateJwk = privateKey.export({
    format: 'jwk',
  })

  const publicJwk = publicKey.export({
    format: 'jwk',
  })

  return {
    privateJwk: privateJwk as Kms.KmsJwkPrivateOkp,
    publicJwk: publicJwk as Kms.KmsJwkPublicOkp,
  }
}

const nodeSupportedOctAlgorithms = ['aes', 'hmac'] satisfies Kms.KmsCreateKeyTypeOct['algorithm'][]
type NodeSupportedOctAlgorithms = (typeof nodeSupportedOctAlgorithms)[number]
export function assertNodeSupportedOctAlgorithm(
  options: Kms.KmsCreateKeyTypeOct
): asserts options is Kms.KmsCreateKeyTypeOct & { algorithm: NodeSupportedOctAlgorithms } {
  if (!nodeSupportedOctAlgorithms.includes(options.algorithm as NodeSupportedOctAlgorithms)) {
    throw new Kms.KeyManagementAlgorithmNotSupportedError(
      `algorithm '${options.algorithm}' for kty '${options.kty}'`,
      'node'
    )
  }
}

export async function createOctKey(options: Kms.KmsCreateKeyTypeOct & { algorithm: NodeSupportedOctAlgorithms }) {
  const secretBytes = randomBytes(options.length >> 3)

  const privateJwk = {
    kty: 'oct',
    k: secretBytes.toString('base64url'),
  }

  const { k, ...publicJwk } = privateJwk

  return {
    privateJwk: privateJwk as Kms.KmsJwkPrivateOct,
    publicJwk: publicJwk as Kms.KmsJwkPublicOct,
  }
}

const nodeSupportedAkpAlgorithms = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] satisfies Kms.KmsCreateKeyTypeAkp['alg'][]
type NodeSupportedAkpAlgorithms = (typeof nodeSupportedAkpAlgorithms)[number]
export function assertNodeSupportedAkpAlgorithm(
  options: Kms.KmsCreateKeyTypeAkp
): asserts options is Kms.KmsCreateKeyTypeAkp & { alg: NodeSupportedAkpAlgorithms } {
  if (!nodeSupportedAkpAlgorithms.includes(options.alg as NodeSupportedAkpAlgorithms)) {
    throw new Kms.KeyManagementAlgorithmNotSupportedError(`alg '${options.alg}' for kty '${options.kty}'`, 'node')
  }
}

export function getMlDsa(algorithm: NodeSupportedAkpAlgorithms) {
  switch (algorithm) {
    case 'ML-DSA-44':
      return ml_dsa44
    case 'ML-DSA-65':
      return ml_dsa65
    case 'ML-DSA-87':
      return ml_dsa87
  }
}

export function createMlDsaPrivateKey(jwk: Kms.KmsJwkPrivateAkp) {
  const mlDsa = getMlDsa(jwk.alg)
  const seed = TypedArrayEncoder.fromBase64Url(jwk.priv)
  if (seed.length !== mlDsa.lengths.seed) throw new Kms.KeyManagementError(`Invalid ${jwk.alg} private key seed length`)

  const keyPair = mlDsa.keygen(seed)
  const publicKey = TypedArrayEncoder.fromBase64Url(jwk.pub)
  if (
    keyPair.publicKey.length !== publicKey.length ||
    keyPair.publicKey.some((byte, index) => byte !== publicKey[index])
  ) {
    throw new Kms.KeyManagementError(`Public key does not match ${jwk.alg} private key seed`)
  }

  return keyPair.secretKey
}

export async function createAkpKey(options: Kms.KmsCreateKeyTypeAkp & { alg: NodeSupportedAkpAlgorithms }) {
  const mlDsa = getMlDsa(options.alg)
  const seedLength = mlDsa.lengths.seed
  if (seedLength === undefined) throw new Kms.KeyManagementError(`Missing ${options.alg} seed length`)
  const seed = randomBytes(seedLength)
  const { publicKey } = mlDsa.keygen(seed)

  return {
    privateJwk: {
      kty: 'AKP',
      alg: options.alg,
      priv: TypedArrayEncoder.toBase64Url(seed),
      pub: TypedArrayEncoder.toBase64Url(publicKey),
    } as Kms.KmsJwkPrivateAkp,
    publicJwk: {
      kty: 'AKP',
      alg: options.alg,
      pub: TypedArrayEncoder.toBase64Url(publicKey),
    } as Kms.KmsJwkPublicAkp,
  }
}
