import { TypedArrayEncoder } from '../../../../../utils'
import { KeyManagementError } from '../../../error/KeyManagementError'
import type { KnownJwaKeyAgreementAlgorithm, KnownJwaSignatureAlgorithm } from '../../jwa'
import type { PublicJwkType } from '../PublicJwk'
import type { KmsJwkPublicAkp } from './akpJwk'

export class AkpPublicJwk implements PublicJwkType<KmsJwkPublicAkp> {
  public static supportedEncryptionKeyAgreementAlgorithms: KnownJwaKeyAgreementAlgorithm[] = []
  public static supportedSignatureAlgorithms: KnownJwaSignatureAlgorithm[] = []
  public static multicodecPrefix = -1

  public multicodecPrefix = AkpPublicJwk.multicodecPrefix
  public supportedEncryptionKeyAgreementAlgorithms = AkpPublicJwk.supportedEncryptionKeyAgreementAlgorithms

  public get supportedSignatureAlgorithms(): KnownJwaSignatureAlgorithm[] {
    return [this.jwk.alg]
  }

  public constructor(public readonly jwk: KmsJwkPublicAkp) {}

  public get publicKey() {
    return {
      kty: this.jwk.kty,
      publicKey: TypedArrayEncoder.fromBase64Url(this.jwk.pub),
    }
  }

  public get compressedPublicKey() {
    return null
  }

  public get multicodec(): Uint8Array {
    throw new KeyManagementError('multicodec not supported for AkpPublicJwk')
  }

  public static fromPublicKey(_publicKey: Uint8Array): AkpPublicJwk {
    throw new KeyManagementError('fromPublicKey not supported for AkpPublicJwk')
  }

  public static fromMulticodec(_multicodec: Uint8Array): AkpPublicJwk {
    throw new KeyManagementError('fromMulticodec not supported for AkpPublicJwk')
  }
}
