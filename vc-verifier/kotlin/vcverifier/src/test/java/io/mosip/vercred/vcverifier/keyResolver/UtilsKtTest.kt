package io.mosip.vercred.vcverifier.keyResolver

import io.ipfs.multibase.Base58
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256K_KEY_TYPE_2019
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_KEY_TYPE
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.testHelpers.assertPublicKey
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.PublicKey
import java.security.interfaces.ECPublicKey

class UtilsKtTest {
    @Test
    fun `test EC secp256k1 public key extraction`() {
        val jwkString = """
    {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "STRMr8BN3ToqGYWQExEm5-mjyiSqq9iGs600-4UMiZY",
        "y": "wMC2jyYYA1UPz5TjeHRkSAZV6y6_C5oyCPsudWtFQPM"
    }
    """.trimIndent()
        val publicKey: PublicKey = getPublicKeyFromJWK(jwkString, ES256K_KEY_TYPE_2019)

        assertNotNull(publicKey)
        assertTrue(publicKey is ECPublicKey)
        assertEquals("EC", publicKey.algorithm)
    }

    @Test
    fun `should correctly generate PublicKey from valid compressed secp256k1 hex`() {
        // Valid compressed secp256k1 public key (33 bytes)
        val compressedHexKey = "034ee0f670fc96bb75e8b89c068a1665007a41c98513d6a911b6137e2d16f1d300"

        val publicKey = getPublicKeyFromHex(compressedHexKey, ES256K_KEY_TYPE_2019)

        assertNotNull(publicKey, "Public key should not be null")
        assertTrue(publicKey is ECPublicKey, "Returned key should be an instance of ECPublicKey")
        assertEquals("EC", publicKey.algorithm)
    }

    @Test
    fun `should return public key for Ed public key in JWK format`() {
        val edPublicKeyJwk = mapOf(
            "kty" to "OKP",
            "crv" to "Ed25519",
            "x" to "8g9d_MB0iU2nmgb_9P4Df0TRQm5RJTmaiEk2HkZy5pE",
            "alg" to "EdDSA",
            "use" to "sig"
        )
        val edPublicKey = getEdPublicKey(edPublicKeyJwk)

        val expectedEncodedPublicKey =
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -14, 15, 93, -4, -64, 116, -119, 77, -89, -102, 6, -1, -12, -2, 3, 127, 68, -47, 66, 110, 81, 37, 57, -102, -120, 73, 54, 30, 70, 114, -26, -111]"
        assertPublicKey(edPublicKey, expectedEncodedPublicKey)
    }

    @Test
    fun `should throw exception when Ed public key in JWK format does not have x`() {
        val edPublicKeyJwk = mapOf(
            "kty" to "OKP",
            "crv" to "Ed25519",
            "alg" to "EdDSA",
            "use" to "sig"
        )
        val publicKeyResolutionFailedException =
            assertThrows<PublicKeyResolutionFailedException> { getEdPublicKey(edPublicKeyJwk) }

        assertEquals(
            "Missing the public key data in JWK",
            publicKeyResolutionFailedException.message
        )
    }

    @Test
    fun `should throw error when curve is not supported`() {
        val edPublicKey = mapOf(
            "kty" to "OKP",
            "crv" to "P-256",
            "x" to "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
        )
        val exception = assertThrows<PublicKeyResolutionFailedException> {
            getEdPublicKey(edPublicKey)
        }

        assertEquals(
            "Curve - P-256 is not supported. Supported: Ed25519",
            exception.message
        )
    }

    @Test
    fun `should throw error when key type is not supported`() {
        val edPublicKey = mapOf(
            "kty" to "EC",
            "crv" to "Ed25519",
            "x" to "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
        )
        val exception = assertThrows<PublicKeyResolutionFailedException> {
            getEdPublicKey(edPublicKey)
        }

        assertEquals(
            "KeyType - EC is not supported. Supported: OKP",
            exception.message
        )
    }

    @Test
    fun `should return Ed public key for hex format input`() {
        val validEdPublicKeyHex = "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"

        val publicKey =
            getEdPublicKeyFromHex(validEdPublicKeyHex)

        assertPublicKey(
            publicKey,
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -14, 15, 93, -4, -64, 116, -119, 77, -89, -102, 6, -1, -12, -2, 3, 127, 68, -47, 66, 110, 81, 37, 57, -102, -120, 73, 54, 30, 70, 114, -26, -111]"
        )
    }

    @Test
    fun `should throw error when public key hex of the Ed key is not 32 bytes`() {
        val invalidEdPublicKeyHex = "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4"

        val exception =
            assertThrows<IllegalArgumentException> { getEdPublicKeyFromHex(invalidEdPublicKeyHex) }

        assertEquals("Ed25519 public key must be 32 bytes", exception.message)
    }

    @Test
    fun `should convert OKP Ed25519 JWK to PublicKey`() {
        val jwkJson = """
        {
            "kty": "OKP",
            "use": "sig",
            "crv": "Ed25519",
            "kid": "sig-2025-10-03T07:54:47Z",
            "x": "IBnBF_cYi78XBsdk3CixMffWjLnBa7eXuXy_h0bLweQ",
            "alg": "EdDSA"
        }
        """.trimIndent()

        val publicKey = jwkToPublicKey(jwkJson)

        val expectedEncoded = "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 32, 25, -63, 23, -9, 24, -117, -65, 23, 6, -57, 100, -36, 40, -79, 49, -9, -42, -116, -71, -63, 107, -73, -105, -71, 124, -65, -121, 70, -53, -63, -28]"
        assertPublicKey(publicKey, expectedEncoded)
    }

    @Test
    fun `should convert EC secp256k1 JWK to PublicKey`() {
        val jwkJson = """
        {
            "kty": "EC",
            "use": "sig",
            "crv": "secp256k1",
            "kid": "sig-2025-10-03T07:53:57Z",
            "x": "arDymovnD_r_nlEtUKxAuEbAop7kgMi2C4GZXTKQZTE",
            "y": "n6SNQaWJYaM4g_-362h_DNa9fRvMrTYqwuAV03-23ns",
            "alg": "ES256K"
        }
        """.trimIndent()

        val publicKey = jwkToPublicKey(jwkJson)

        val expectedEncoded =
            "[48, 86, 48, 16, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 5, 43, -127, 4, 0, 10, 3, 66, 0, 4, 106, -80, -14, -102, -117, -25, 15, -6, -1, -98, 81, 45, 80, -84, 64, -72, 70, -64, -94, -98, -28, -128, -56, -74, 11, -127, -103, 93, 50, -112, 101, 49, -97, -92, -115, 65, -91, -119, 97, -93, 56, -125, -1, -73, -21, 104, 127, 12, -42, -67, 125, 27, -52, -83, 54, 42, -62, -32, 21, -45, 127, -74, -34, 123]"
        assertPublicKey(publicKey, expectedEncoded)
    }

    @Test
    fun `should convert RSA JWK to PublicKey`() {
        val jwkJson = """
        {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "sig-2025-10-03T07:52:47Z",
            "alg": "PS256",
            "n": "gZqNrF9_CHZH8yukFNbJ79BPrNYpnf6wxqr-CZBmAUU6OoKPeHJGt8zs3bShxOfTCROn9698oOi0rMUJDmNelShPBt5D-e3iKLy0qTeVl7zcBZ8crG-jI1Io2zIIFOxL2Ms9oT28Uqk77IJ6bnM6KgNXBV-zEcSVX2Z49mx6EB13oIxR0j8UXBkQXvZ-ltpFA87z_NGYxA21-NC0XZlUS9E5-IzaRF-IKHl0G13iFvuUGull6HmgttoP8s1orp2m-naPIOZ_5dT4nOCOHwPXRg_jMVkm6JBL2YYBsgOVSGHQESiW6Harv3Z1GsH5CYRnB3gWlPs1_1UdWC18zBjxmw"
        }
        """.trimIndent()

        val publicKey = jwkToPublicKey(jwkJson)

        val expectedEncoded =
            "[48, -126, 1, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -126, 1, 15, 0, 48, -126, 1, 10, 2, -126, 1, 1, 0, -127, -102, -115, -84, 95, 127, 8, 118, 71, -13, 43, -92, 20, -42, -55, -17, -48, 79, -84, -42, 41, -99, -2, -80, -58, -86, -2, 9, -112, 102, 1, 69, 58, 58, -126, -113, 120, 114, 70, -73, -52, -20, -35, -76, -95, -60, -25, -45, 9, 19, -89, -9, -81, 124, -96, -24, -76, -84, -59, 9, 14, 99, 94, -107, 40, 79, 6, -34, 67, -7, -19, -30, 40, -68, -76, -87, 55, -107, -105, -68, -36, 5, -97, 28, -84, 111, -93, 35, 82, 40, -37, 50, 8, 20, -20, 75, -40, -53, 61, -95, 61, -68, 82, -87, 59, -20, -126, 122, 110, 115, 58, 42, 3, 87, 5, 95, -77, 17, -60, -107, 95, 102, 120, -10, 108, 122, 16, 29, 119, -96, -116, 81, -46, 63, 20, 92, 25, 16, 94, -10, 126, -106, -38, 69, 3, -50, -13, -4, -47, -104, -60, 13, -75, -8, -48, -76, 93, -103, 84, 75, -47, 57, -8, -116, -38, 68, 95, -120, 40, 121, 116, 27, 93, -30, 22, -5, -108, 26, -23, 101, -24, 121, -96, -74, -38, 15, -14, -51, 104, -82, -99, -90, -6, 118, -113, 32, -26, 127, -27, -44, -8, -100, -32, -114, 31, 3, -41, 70, 15, -29, 49, 89, 38, -24, -112, 75, -39, -122, 1, -78, 3, -107, 72, 97, -48, 17, 40, -106, -24, 118, -85, -65, 118, 117, 26, -63, -7, 9, -124, 103, 7, 120, 22, -108, -5, 53, -1, 85, 29, 88, 45, 124, -52, 24, -15, -101, 2, 3, 1, 0, 1]"
        assertPublicKey(publicKey, expectedEncoded)
    }

    @Test
    fun `should throw for unsupported key type`() {
        val jwkJson = """
        {
          "kty": "oct",
          "k": "GawgguFyGrWKav7AX4VKUg"
        }
        """.trimIndent()

        assertThrows<PublicKeyTypeNotSupportedException> {
            jwkToPublicKey(jwkJson)
        }
    }

    @Test
    fun `getPublicKeyObjectFromPublicKeyMultibase throws PublicKeyNotFoundException when RSA has invalid multicodec header`() {
        val invalidHeader = byteArrayOf(0x00, 0x00) // wrong header bytes
        val fakeRsaKeyBody = ByteArray(32) { it.toByte() }
        val rawBytes = invalidHeader + fakeRsaKeyBody

        val multibaseEncoded = "z" + Base58.encode(rawBytes)

        val exception = assertThrows<PublicKeyNotFoundException> {
            getPublicKeyObjectFromPublicKeyMultibase(multibaseEncoded, RSA_KEY_TYPE)
        }

        assertEquals("Public key object is null: Invalid RSA multicodec header", exception.message)
    }

    @Test
    fun `getPublicKeyObjectFromPublicKeyMultibase throws PublicKeyNotFoundException when key type is unsupported`() {
        val rawBytes = ByteArray(34) { it.toByte() } // dummy bytes, content doesn't matter
        val multibaseEncoded = "z" + Base58.encode(rawBytes)

        val exception = assertThrows<PublicKeyNotFoundException> {
            getPublicKeyObjectFromPublicKeyMultibase(multibaseEncoded, "UNSUPPORTED_KEY_TYPE")
        }

        assertEquals("Public key object is null: Unsupported key type: UNSUPPORTED_KEY_TYPE", exception.message)
    }
}