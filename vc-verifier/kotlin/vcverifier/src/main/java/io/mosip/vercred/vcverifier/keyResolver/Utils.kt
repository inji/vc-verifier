package io.mosip.vercred.vcverifier.keyResolver

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import io.ipfs.multibase.Base58
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.COMPRESSED_HEX_KEY_LENGTH
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2018
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_PROOF_TYPE_2018
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_PROOF_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED_DER_PUBLIC_KEY_PREFIX
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256K_KEY_TYPE_2019
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256K_PROOF_TYPE_2019
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256_KEY_TYPE_2019
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256_PROOF_TYPE_2019
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWK_KEY_TYPE_EC
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256K_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.P256
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.P256_DER_PUBLIC_KEY_PREFIX
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_MULTICODEC_FIRST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_MULTICODEC_SECOND
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_PROOF_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.SECP256K1
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import io.mosip.vercred.vcverifier.signature.bouncyCastleProvider
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.io.pem.PemReader
import java.io.StringReader
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.logging.Logger


private val base64Decoder = Base64Decoder()

private val logger = Logger.getLogger("KeyResolverUtils")

private val X509_HEADER_PREFIX_ED_KEY = byteArrayOf(
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03,
    0x2B, 0x65, 0x70, 0x03, 0x21, 0x00
)

private var provider: BouncyCastleProvider = BouncyCastleProvider()

private val PUBLIC_KEY_ALGORITHM: Map<String, String> = mapOf(
    RSA_KEY_TYPE to RSA_ALGORITHM,
    ED25519_KEY_TYPE_2018 to ED25519_ALGORITHM,
    ED25519_KEY_TYPE_2020 to ED25519_ALGORITHM,
    ES256_KEY_TYPE_2019 to JWK_KEY_TYPE_EC,
)

fun getJwsAlgorithmFromProofType(proofType: String): String {
    return when (proofType) {
        ED25519_PROOF_TYPE_2018, ED25519_PROOF_TYPE_2020 -> JWS_EDDSA_SIGN_ALGO_CONST
        ES256K_PROOF_TYPE_2019 -> JWS_ES256K_SIGN_ALGO_CONST
        ES256_PROOF_TYPE_2019 -> JWS_ES256_SIGN_ALGO_CONST
        RSA_PROOF_TYPE -> JWS_RS256_SIGN_ALGO_CONST
        else -> throw SignatureNotSupportedException("Unsupported signature suite")
    }
}

private const val SECP256K1_PRIME_MODULUS =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"

fun getPublicKeyObjectFromPemPublicKey(publicKeyPem: String, keyType: String): PublicKey {
    try {
        val strReader = StringReader(publicKeyPem)
        val pemReader = PemReader(strReader)
        val pemObject = pemReader.readPemObject()
        val pubKeyBytes = pemObject.content
        val pubKeySpec = X509EncodedKeySpec(pubKeyBytes)
        val keyFactory = KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM[keyType], provider)
        return keyFactory.generatePublic(pubKeySpec)
    } catch (e: Exception) {
        logger.severe("Error while getting public key object from PEM: ${e.message}")
        throw PublicKeyNotFoundException("Public key object is null")
    }
}

fun getPublicKeyFromJWK(jwk: Map<String, Any>, keyType: String): PublicKey {
    return when (keyType) {
        ES256K_KEY_TYPE_2019,ES256_KEY_TYPE_2019,JWK_KEY_TYPE_EC  -> getECPublicKey(jwk)
        ED25519_KEY_TYPE_2020, "OKP" -> getEdPublicKey(jwk)
        RSA_KEY_TYPE, RSA_ALGORITHM -> getRSAPublicKey(jwk)
        else -> throw PublicKeyTypeNotSupportedException("Unsupported key type: $keyType")
    }
}


fun getPublicKeyFromJWK(jwkStr: String, keyType: String): PublicKey {
    val objectMapper = ObjectMapper()
    val jwk: Map<String, Any> =
        objectMapper.readValue(jwkStr, Map::class.java) as Map<String, Any>

    return when (keyType) {
        ES256K_KEY_TYPE_2019,ES256_KEY_TYPE_2019,JWK_KEY_TYPE_EC  -> getECPublicKey(jwk)
        ED25519_KEY_TYPE_2020, "OKP" -> getEdPublicKey(jwk)
        RSA_KEY_TYPE, RSA_ALGORITHM -> getRSAPublicKey(jwk)
        else -> throw PublicKeyTypeNotSupportedException("Unsupported key type: $keyType")
    }
}

private fun getRSAPublicKey(jwk: Map<String, Any>): PublicKey {
    val nB64Url = jwk["n"]?.toString() ?: throw PublicKeyResolutionFailedException("Missing modulus 'n' in JWK for RSA key")
    val eB64Url = jwk["e"]?.toString() ?: throw PublicKeyResolutionFailedException("Missing exponent 'e' in JWK for RSA key")

    val modulus = BigInteger(1, base64Decoder.decodeFromBase64Url(nB64Url))
    val exponent = BigInteger(1, base64Decoder.decodeFromBase64Url(eB64Url))

    val keySpec = java.security.spec.RSAPublicKeySpec(modulus, exponent)
    val keyFactory = KeyFactory.getInstance("RSA", provider)
    return keyFactory.generatePublic(keySpec)
}


internal fun getEdPublicKey(jwk: Map<String, Any>): PublicKey {
    val keyType = jwk["kty"]
    require(keyType == "OKP") { throw PublicKeyResolutionFailedException("KeyType - $keyType is not supported. Supported: OKP") }
    val curve = jwk["crv"]
    require(curve == ED25519_ALGORITHM) { throw PublicKeyResolutionFailedException("Curve - $curve is not supported. Supported: Ed25519") }

    val xB64Url =
        jwk["x"] ?: throw PublicKeyResolutionFailedException("Missing the public key data in JWK")
    val xB64 = xB64Url.toString()
    val xBytes = base64Decoder.decodeFromBase64Url(xB64)

    val spki = X509_HEADER_PREFIX_ED_KEY + xBytes

    val keySpec = X509EncodedKeySpec(spki)
    return KeyFactory.getInstance(ED25519_ALGORITHM, provider).generatePublic(keySpec)
}


private fun getECPublicKey(jwk: Map<String, Any>): PublicKey {
    val curve = jwk["crv"]?.toString() ?: throw IllegalArgumentException("Missing 'crv' field for EC key")

    val xBase64 = jwk["x"]?.toString()
        ?: throw PublicKeyResolutionFailedException("Missing 'x'")

    val yBase64 = jwk["y"]?.toString()
        ?: throw PublicKeyResolutionFailedException("Missing 'y'")
    val xBytes = Base64Decoder().decodeFromBase64Url(xBase64)
    val yBytes = Base64Decoder().decodeFromBase64Url(yBase64)

    val x = BigInteger(1, xBytes)
    val y = BigInteger(1, yBytes)
    val ecPoint = ECPoint(x, y)

    val ecSpec = when (curve) {
        SECP256K1 -> ECNamedCurveTable.getParameterSpec(SECP256K1)
        P256 -> ECNamedCurveTable.getParameterSpec(P256)
        else -> throw IllegalArgumentException("Unsupported EC curve: $curve")
    }

    val ecParameterSpec = ECNamedCurveSpec(curve, ecSpec.curve, ecSpec.g, ecSpec.n, ecSpec.h, ecSpec.seed)
    val pubKeySpec = ECPublicKeySpec(ecPoint, ecParameterSpec)
    val keyFactory = KeyFactory.getInstance(JWK_KEY_TYPE_EC, provider)
    return keyFactory.generatePublic(pubKeySpec)
}

fun getPublicKeyObjectFromPublicKeyMultibase(publicKeyMultibase: String, keyType: String): PublicKey {
    try {
        val rawPublicKeyWithHeader = Base58.decode(publicKeyMultibase.substring(1))

        val publicKeyBytes = when (keyType) {

            ED25519_KEY_TYPE_2020 -> {
                val raw = rawPublicKeyWithHeader.copyOfRange(2, rawPublicKeyWithHeader.size)
                Hex.decode(ED_DER_PUBLIC_KEY_PREFIX) + raw
            }

            ES256_KEY_TYPE_2019 -> {
                val raw = rawPublicKeyWithHeader.copyOfRange(2, rawPublicKeyWithHeader.size)
                val decompressed = decompressP256Key(raw)
                Hex.decode(P256_DER_PUBLIC_KEY_PREFIX) + decompressed
            }

            RSA_KEY_TYPE -> {
                if (rawPublicKeyWithHeader[0] != RSA_MULTICODEC_FIRST ||
                    rawPublicKeyWithHeader[1] != RSA_MULTICODEC_SECOND
                ) {
                    throw PublicKeyTypeNotSupportedException("Invalid RSA multicodec header")
                }

                rawPublicKeyWithHeader.copyOfRange(2, rawPublicKeyWithHeader.size)
            }

            else -> throw PublicKeyTypeNotSupportedException("Unsupported key type: $keyType")
        }

        val pubKeySpec = X509EncodedKeySpec(publicKeyBytes)
        val keyFactory = KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM[keyType], provider)

        return keyFactory.generatePublic(pubKeySpec)

    } catch (e: Exception) {
        logger.severe("Error while getting public key object from Multibase: ${e.message}")
        throw PublicKeyNotFoundException("Public key object is null: ${e.message}")
    }
}

internal fun decompressP256Key(compressed: ByteArray): ByteArray {
    val params = ECNamedCurveTable.getParameterSpec("secp256r1")
    val curve = params.curve

    val point: org.bouncycastle.math.ec.ECPoint? = curve.decodePoint(compressed)
    return point?.getEncoded(false) ?: throw IllegalArgumentException("Invalid compressed EC point")
}
fun getPublicKeyFromHex(hexKey: String, keyType: String): PublicKey {
    return when (keyType) {
        ES256_KEY_TYPE_2019 -> getECR1PublicKeyFromHex(hexKey)
        ES256K_KEY_TYPE_2019 -> getECK1PublicKeyFromHex(hexKey)
        ED25519_KEY_TYPE_2020 -> getEdPublicKeyFromHex(hexKey)
        else -> throw PublicKeyTypeNotSupportedException("Unsupported key type: $keyType")
    }
}

internal fun getEdPublicKeyFromHex(hexKey: String): PublicKey {
    val pubKeyBytes = hexKey.chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

    require(pubKeyBytes.size == 32) { "Ed25519 public key must be 32 bytes" }

    val spki = X509_HEADER_PREFIX_ED_KEY + pubKeyBytes
    val keySpec = X509EncodedKeySpec(spki)

    return KeyFactory.getInstance(ED25519_ALGORITHM, provider).generatePublic(keySpec)
}

fun getECK1PublicKeyFromHex(hexKey: String): PublicKey {
    val keyFactory = KeyFactory.getInstance(JWK_KEY_TYPE_EC, provider)
    val keyBytes = hexStringToByteArray(hexKey)
    val ecPoint = decodeSecp256k1PublicKey(keyBytes)
    val ecSpec = secp256k1Params()
    val pubKeySpec = ECPublicKeySpec(ecPoint, ecSpec)

    return keyFactory.generatePublic(pubKeySpec) as ECPublicKey
}

fun getECR1PublicKeyFromHex(hexKey: String): PublicKey {
    val keyFactory = KeyFactory.getInstance(JWK_KEY_TYPE_EC, provider)
    val keyBytes = hexStringToByteArray(hexKey)

    val ecPoint = decodeP256PublicKey(keyBytes)

    val params = ECNamedCurveTable.getParameterSpec("secp256r1")

    val ecSpec = ECNamedCurveSpec(
        "secp256r1",
        params.curve,
        params.g,
        params.n,
        params.h
    )

    val pubKeySpec = ECPublicKeySpec(ecPoint, ecSpec)

    return keyFactory.generatePublic(pubKeySpec)
}

private fun decodeP256PublicKey(keyBytes: ByteArray): ECPoint {
    val params = ECNamedCurveTable.getParameterSpec("secp256r1")
    val point = params.curve.decodePoint(keyBytes)

    return ECPoint(point.xCoord.toBigInteger(), point.yCoord.toBigInteger())
}

private fun hexStringToByteArray(hex: String): ByteArray {
    return BigInteger(hex, 16).toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
}


private fun decodeSecp256k1PublicKey(keyBytes: ByteArray): ECPoint {
    require(keyBytes.size == COMPRESSED_HEX_KEY_LENGTH) { "Invalid compressed public key length" }
    require(keyBytes[0] == 0x02.toByte() || keyBytes[0] == 0x03.toByte()) { "Invalid compressed public key prefix" }

    val x = BigInteger(1, keyBytes.copyOfRange(1, keyBytes.size))
    val y = recoverYCoordinate(x, keyBytes[0] == 3.toByte())

    return ECPoint(x, y)
}

// Recover the Y-coordinate from X using the Secp256k1 curve equation
private fun recoverYCoordinate(x: BigInteger, odd: Boolean): BigInteger {
    val p = BigInteger(SECP256K1_PRIME_MODULUS, 16)
    val b = BigInteger.valueOf(7)

    val rhs = (x.modPow(BigInteger.valueOf(3), p).add(b)).mod(p)
    val y = rhs.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p)

    return if (y.testBit(0) == odd) y else p.subtract(y)
}

private fun secp256k1Params(): ECParameterSpec {
    val params = ECNamedCurveTable.getParameterSpec(SECP256K1)
    return ECNamedCurveSpec(SECP256K1, params.curve, params.g, params.n, params.h)
}


fun jwkToPublicKey(jwkJson: String): PublicKey {
    val jwk: JWK = JWK.parse(jwkJson)

    return when (jwk.keyType) {
        KeyType.OKP -> getPublicKeyFromJWK(jwkJson, ED25519_KEY_TYPE_2020)
        KeyType.EC -> getPublicKeyFromJWK(jwkJson, ES256K_KEY_TYPE_2019)
        KeyType.RSA -> getPublicKeyFromJWK(jwkJson, RSA_KEY_TYPE)
        else -> throw PublicKeyTypeNotSupportedException(
            "KeyType - ${jwk.keyType} is not supported. Supported: OKP, EC, RSA"
        )
    }
}
