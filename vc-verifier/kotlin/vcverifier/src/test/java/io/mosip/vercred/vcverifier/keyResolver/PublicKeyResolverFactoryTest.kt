package io.mosip.vercred.vcverifier.keyResolver

import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_PEM
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.networkManager.HttpMethod
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.vercred.vcverifier.testHelpers.assertPublicKey
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URI

class PublicKeyResolverFactoryTest {

    private val factory = PublicKeyResolverFactory()

    @BeforeEach
    fun setUp() {
        mockkObject(NetworkManagerClient.Companion)
    }

    @Test
    fun `should use DidWebPublicKeyResolver for did_web`() {
        val mockResponse = mapOf(
            "id" to "did:web:example.com",
            "verificationMethod" to listOf(
                mapOf(
                    "id" to "did:web:example.com",
                    "type" to "Ed25519VerificationKey2020",
                    "controller" to "did:web:example.com",
                    "publicKeyMultibase" to "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
                )
            )
        )
        every {
            sendHTTPRequest(
                "https://example.com/.well-known/did.json",
                HttpMethod.GET
            )
        } returns mockResponse
        val uri = URI("did:web:example.com")

        assertDoesNotThrow { factory.get(uri) }
    }

    @Test
    fun `should use DidKeyPublicKeyResolver for did_key`() {
        val didKey = URI("did:key:z6MkpiJgQdNWUzyojaFuCzQ1MWvSSaxUfL1tvbcRfqWFoJRK")
        val expectedEncodedPublicKey =
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -104, 111, -113, -128, 30, 39, -124, -13, 109, 42, -42, -40, -42, 108, 43, 71, -113, 52, 13, 48, -52, 87, 69, -103, 118, 53, 52, 53, 86, 66, -93, 22]"

        val publicKey = factory.get(didKey)

        assertPublicKey(publicKey, expectedEncodedPublicKey)
    }

    @Test
    fun `should use DidJwkPublicKeyResolver for did_jwk`() {
        val didJwk =
            URI("did:jwk:eyJrdHkiOiAiT0tQIiwgImNydiI6ICJFZDI1NTE5IiwgIngiOiAiOGc5ZF9NQjBpVTJubWdiXzlQNERmMFRSUW01UkpUbWFpRWsySGtaeTVwRSIsICJhbGciOiAiRWREU0EiLCAia2V5X29wcyI6IFsidmVyaWZ5Il0sICJ1c2UiOiAic2lnIn0")
        val expectedEncodedPublicKey =
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -14, 15, 93, -4, -64, 116, -119, 77, -89, -102, 6, -1, -12, -2, 3, 127, 68, -47, 66, 110, 81, 37, 57, -102, -120, 73, 54, 30, 70, 114, -26, -111]"

        val publicKey = factory.get(didJwk)

        assertPublicKey(publicKey, expectedEncodedPublicKey)
    }

    @Test
    fun `should use HttpsPublicKeyResolver for http`() {
        val httpsVerificationMethodUri = "https://mock-server.com/.well-known/did.json"
        val mockResponse = mapOf(
            PUBLIC_KEY_PEM to "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=\n-----END PUBLIC KEY-----",
            KEY_TYPE to ED25519_KEY_TYPE_2020
        )
        every { sendHTTPRequest(httpsVerificationMethodUri, HttpMethod.GET, any(), any()) } returns mockResponse

        val uri = URI(httpsVerificationMethodUri)

        assertDoesNotThrow { factory.get(uri) }
    }

    @Test
    fun `should throw exception for unsupported type`() {
        val uri = URI("foo:bar:baz")

        val publicKeyTypeNotSupportedException =
            assertThrows(PublicKeyTypeNotSupportedException::class.java) {
                factory.get(uri)
            }

        assertEquals("Public Key type is not supported", publicKeyTypeNotSupportedException.message)
    }

    @Test
    fun `should use JwksPublicKeyResolver when keyId is provided`() {
        val jwksUri = URI("https://mock-server.com/.well-known/jwks.json")
        val keyId = "test-key-id"

        val mockResponse = mapOf(
            "keys" to listOf(
                mapOf(
                    "kty" to "OKP",
                    "crv" to "Ed25519",
                    "x" to "8g9d_MB0iU2nmgb_9P4Df0TRQm5RJTmaiEk2HkZy5pE",
                    "kid" to keyId
                )
            )
        )

        every {
            sendHTTPRequest(jwksUri.toString(), HttpMethod.GET, any(), any())
        } returns mockResponse

        assertDoesNotThrow {
            factory.get(jwksUri, keyId)
        }
    }

}