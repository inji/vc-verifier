package io.mosip.vercred.vcverifier.keyResolver.types.did

import io.ipfs.multibase.Multibase
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWK_KEY_TYPE_EC
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays

private const val MULTIBASE_KEY_SIZE = 34
private const val ED_KEY_PREFIX = 0xed.toByte()
private const val MULTICODEC_TRAILING_BYTE = 0x01.toByte()

private const val P256_KEY_PREFIX_FIRST = 0x80.toByte()
private const val P256_KEY_PREFIX_SECOND = 0x24.toByte()
class DidKeyPublicKeyResolver : DidPublicKeyResolver() {
    private val provider: BouncyCastleProvider = BouncyCastleProvider()

    override fun extractPublicKey(parsedDID: ParsedDID, keyId: String?): PublicKey {
        val decodedKey = Multibase.decode(parsedDID.id)

        return when {
            isEd25519KeyType(decodedKey) -> extractEd25519Key(decodedKey)
            isP256KeyType(decodedKey) -> extractP256Key(decodedKey)
            else -> {
                throw PublicKeyTypeNotSupportedException(
                    message = "KeyType - ${decodedKey[0]} is not supported. Supported: ed25519, ecr1"
                )
            }
        }
    }

    private fun extractEd25519Key(decodedKey: ByteArray): PublicKey {
        val publicKeyBytes = Arrays.copyOfRange(decodedKey, 2, MULTIBASE_KEY_SIZE)

        val algorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
        val subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithmIdentifier, publicKeyBytes)

        val encodedKey = subjectPublicKeyInfo.encoded
        val keySpec = X509EncodedKeySpec(encodedKey)

        val keyFactory = KeyFactory.getInstance(JWS_EDDSA_SIGN_ALGO_CONST, provider)
        return keyFactory.generatePublic(keySpec)
    }

    private fun extractP256Key(decodedKey: ByteArray): PublicKey {
        val publicKeyBytes = Arrays.copyOfRange(decodedKey, 2, decodedKey.size)

        val algorithmIdentifier = AlgorithmIdentifier(
            org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_ecPublicKey,
            org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp256r1
        )

        val subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithmIdentifier, publicKeyBytes)
        val encodedKey = subjectPublicKeyInfo.encoded

        val keySpec = X509EncodedKeySpec(encodedKey)
        val keyFactory = KeyFactory.getInstance(JWK_KEY_TYPE_EC, provider)

        return keyFactory.generatePublic(keySpec)
    }

    private fun isEd25519KeyType(decodedKey: ByteArray) =
        (decodedKey[0] == ED_KEY_PREFIX && decodedKey[1] == MULTICODEC_TRAILING_BYTE) && decodedKey.size == MULTIBASE_KEY_SIZE

    private fun isP256KeyType(decodedKey: ByteArray) =
        decodedKey[0] == P256_KEY_PREFIX_FIRST &&
                decodedKey[1] == P256_KEY_PREFIX_SECOND
}