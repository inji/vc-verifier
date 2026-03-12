package io.mosip.vercred.vcverifier.keyResolver.types.did

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256K_KEY_TYPE_2019
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256_KEY_TYPE_2019
import io.mosip.vercred.vcverifier.constants.DidMethod
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.networkManager.HttpMethod
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.vercred.vcverifier.testHelpers.assertPublicKey
import io.mosip.vercred.vcverifier.testHelpers.encodedEcP256PublicKey
import io.mosip.vercred.vcverifier.testHelpers.encodedEcdsaPublicKey
import io.mosip.vercred.vcverifier.testHelpers.encodedEd25519PublicKey
import io.mosip.vercred.vcverifier.testHelpers.validDidWeb
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.PublicKey


class DidWebPublicKeyResolverTest {
    private val resolver = DidWebPublicKeyResolver()
    private val didJsonWellKnown = "https://example.com/.well-known/did.json"

    private val validDid = "$validDidWeb#key-1"
    private fun didDocWithMethod(method: Map<String, Any>) =
        mapOf("verificationMethod" to listOf(method))

    @BeforeEach
    fun setUp() {
        mockkObject(NetworkManagerClient.Companion)
    }

    @AfterEach
    fun tearDown() {
        clearAllMocks()
        unmockkAll()
    }

    // Key type - Ed25519VerificationKey2020

    @Test
    fun `should resolve public key from PEM of Ed25519 key type`() {
        val pem =
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=\n-----END PUBLIC KEY-----"
        mockDidDocument(mapOf("publicKeyPem" to pem))

        val publicKey = resolver.extractPublicKey(createParsedDid())

        assertPublicKey(publicKey, encodedEd25519PublicKey)
    }

    @Test
    fun `should resolve public key from multibase of Ed25519 key type`() {
        val publicKeyMultibaseInfo = mapOf(
            "publicKeyMultibase" to "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        )
        mockDidDocument(publicKeyMultibaseInfo)
        val expectedEncodedPublicKey =
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -108, -106, 107, 124, 8, -28, 5, 119, 95, -115, -26, -52, 28, 69, 8, -10, -21, 34, 116, 3, -31, 2, 91, 44, -118, -46, -41, 71, 115, -104, -59, -78]"

        val publicKey = resolver.extractPublicKey(createParsedDid())

        assertPublicKey(publicKey, expectedEncodedPublicKey)
    }

    @Test
    fun `should resolve publicKeyJwk of Ed25519 key type`() {
        val publicKeyJwkInfo = mapOf(
            "publicKeyJwk" to """
            {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "8g9d_MB0iU2nmgb_9P4Df0TRQm5RJTmaiEk2HkZy5pE",
                    "alg": "EdDSA",
                    "use": "sig"
                }
        """.trimIndent()
        )
        mockDidDocument(publicKeyJwkInfo)

        val publicKey = resolver.extractPublicKey(createParsedDid())

        assertPublicKey(publicKey, encodedEd25519PublicKey)
    }

    @Test
    fun `should resolve publicKeyHex of Ed25519 key type`() {
        val publicKeyHexInfo = mapOf(
            "publicKeyHex" to "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691",
        )
        mockDidDocument(publicKeyHexInfo)

        val resolvedPublicKey: PublicKey = resolver.extractPublicKey(createParsedDid())

        assertPublicKey(resolvedPublicKey, encodedEd25519PublicKey)
    }
    // Key type - EcdsaSecp256r1VerificationKey2019 (P-256 / ES256)

    @Test
    fun `should resolve public key from PEM of ECR1 key type`() {
        val pem =
            "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErw8pST9k/peYjQscA9h1AHCC04yO\n8z/FcbzaXMjJavWQUEufNVd9B6/4BlA9v86aEEql1RSCU7m3v+GaRxrvIw==\n-----END PUBLIC KEY-----"
        mockDidDocument(mapOf("publicKeyPem" to pem), ES256_KEY_TYPE_2019)

        val publicKey = resolver.extractPublicKey(createParsedDid())

        assertPublicKey(publicKey, encodedEcP256PublicKey)
    }

    @Test
    fun `should resolve public key from multibase of ECR1 key type`() {
        val publicKeyMultibaseInfo = mapOf(
            "publicKeyMultibase" to "zDnaeuSeAxxoAznJQNqSx1iHYJ55wiHbv4VcTDUZQrbPGTZMn",
        )
        mockDidDocument(publicKeyMultibaseInfo, ES256_KEY_TYPE_2019)

        val publicKey = resolver.extractPublicKey(createParsedDid())

        assertPublicKey(publicKey, encodedEcP256PublicKey)
    }

    @Test
    fun `should resolve public key from JWK of ECR1 key type`() {
        val publicKeyJwkInfo = mapOf(
            "publicKeyJwk" to """
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "rw8pST9k_peYjQscA9h1AHCC04yO8z_FcbzaXMjJavU",
            "y": "kFBLnzVXfQev-AZQPb_OmhBKpdUUglO5t7_hmkca7yM",
            "alg": "ES256",
            "use": "sig"
        }
    """.trimIndent()
        )
        mockDidDocument(publicKeyJwkInfo, ES256_KEY_TYPE_2019)

        val publicKey = resolver.extractPublicKey(createParsedDid())

        assertPublicKey(publicKey, encodedEcP256PublicKey)
    }

    @Test
    fun `should resolve public key from HEX of ECR1 key type`() {
        val publicKeyHexInfo = mapOf(
            "publicKeyHex" to "03af0f29493f64fe97988d0b1c03d875007082d38c8ef33fc571bcda5cc8c96af5",
        )
        mockDidDocument(publicKeyHexInfo, ES256_KEY_TYPE_2019)

        val publicKey = resolver.extractPublicKey(createParsedDid())

        assertPublicKey(publicKey, encodedEcP256PublicKey)
    }

    // Key type - EcdsaSecp256k1VerificationKey2019

    @Test
    fun `should resolve public key from JWK of ES256K key type`() {
        val publicKeyJwkInfo = mapOf(
            "publicKeyJwk" to """
            {
                "kty": "EC",
                "use": "sig",
                "crv": "secp256k1",
                "kid": "sig-1755418456",
                "x": "2-LgLeBUdAXGKuhGRuXL2OmoOLOOA6gD9TcX0zLwOjY",
                "y": "ZDtDKZNZQxtTo628V5nlaKDG2QiURVPje22p6CmNjdo",
                "alg": "ES256K"
            }
        """.trimIndent()
        )
        mockDidDocument(publicKeyJwkInfo, ES256K_KEY_TYPE_2019)

        val resolvedPublicKey = resolver.extractPublicKey(createParsedDid())

        assertPublicKey(resolvedPublicKey, encodedEcdsaPublicKey)
    }


    @Test
    fun `should resolve public key from HEX of ES256K key type`() {
        val publicKeyHexInfo = mapOf(
            "publicKeyHex" to "02dbe2e02de0547405c62ae84646e5cbd8e9a838b38e03a803f53717d332f03a36",
        )
        mockDidDocument(publicKeyHexInfo, ES256K_KEY_TYPE_2019)

        val resolvedPublicKey = resolver.extractPublicKey(createParsedDid())

        assertPublicKey(resolvedPublicKey, encodedEcdsaPublicKey)
    }

    // Common Did resolution tests

    @Test
    fun `should resolve public key for the provided key id`() {
        val publicKeyHexInfo = mapOf(
            "publicKeyHex" to "02dbe2e02de0547405c62ae84646e5cbd8e9a838b38e03a803f53717d332f03a36",
        )
        val publicKeyInfo1 =
            mapOf("id" to "$validDidWeb#key-1", "type" to ES256K_KEY_TYPE_2019) + publicKeyHexInfo
        val publicKeyInfo2 =
            mapOf("id" to "$validDidWeb#key-2", "type" to ES256K_KEY_TYPE_2019) + publicKeyHexInfo
        val verificationMethods =
            mapOf("verificationMethod" to listOf(publicKeyInfo1, publicKeyInfo2))
        every {
            sendHTTPRequest(
                didJsonWellKnown,
                HttpMethod.GET
            )
        } returns verificationMethods
        val parsedDID = ParsedDID(
            "$validDidWeb#key-2",
            DidMethod.WEB,
            "example.com",
            "$validDidWeb#key-2",
        )

        val resolvedPublicKey = resolver.extractPublicKey(parsedDID, "$validDidWeb#key-2")

        assertPublicKey(resolvedPublicKey, encodedEcdsaPublicKey)
    }

    @Test
    fun `should throw when provided key Id is not found in the did document`() {
        val publicKeyHexInfo = mapOf(
            "publicKeyHex" to "02dbe2e02de0547405c62ae84646e5cbd8e9a838b38e03a803f53717d332f03a36",
        )
        mockDidDocument(publicKeyHexInfo, ES256K_KEY_TYPE_2019)
        val parsedDID = ParsedDID(
            validDidWeb,
            DidMethod.WEB,
            "example.com",
            validDidWeb,
        )

        val keyResolutionFailedException =
            assertThrows(PublicKeyResolutionFailedException::class.java) {
                resolver.extractPublicKey(parsedDID, "$validDidWeb#key-2")
            }
        assertEquals(
            "Public key extraction failed for kid: did:web:example.com#key-2",
            keyResolutionFailedException.message
        )
    }

    @Test
    fun `should throw when verification method not found`() {
        every {
            sendHTTPRequest(
                didJsonWellKnown,
                HttpMethod.GET
            )
        } returns emptyMap()

        val ex = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.extractPublicKey(createParsedDid())
        }
        assertTrue(ex.message!!.contains("Verification method not found"))
    }

    @Test
    fun `should throw when no matching verification method when didUrl and id in verification method is not matching`() {
        val verificationMaterial = mapOf("id" to "did:web:example.com#other-key")
        mockDidDocument(verificationMaterial)

        val ex = assertThrows(PublicKeyResolutionFailedException::class.java) {
            resolver.extractPublicKey(createParsedDid())
        }
        assertEquals("Public key extraction failed for kid: did:web:example.com#key-1", ex.message)
    }

    @Test
    fun `should throw error when verification method does not have any public key material`() {
        val didWithNoPublicKeyMaterial = validDid
        val method = mapOf("id" to didWithNoPublicKeyMaterial)
        mockDidDocument(method)

        val publicKeyNotFoundException = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.extractPublicKey(createParsedDid())
        }
        assertTrue(publicKeyNotFoundException.message!!.contains("None of the provided keys"))
    }

    @Test
    fun `should throw when public key type is not supported`() {
        val unsupportedTypeVerificationMaterial =
            mapOf("id" to validDid, "unsupportedKey" to "value")
        mockDidDocument(unsupportedTypeVerificationMaterial)

        val exception = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.extractPublicKey(createParsedDid())
        }
        assertEquals(
            "None of the provided keys were found in verification method",
            exception.message
        )
    }

    @Test
    fun `should throw PublicKeyNotFoundException on network call to resolve did document fails`() {
        every {
            sendHTTPRequest(
                didJsonWellKnown,
                HttpMethod.GET
            )
        } throws RuntimeException("network error")

        val ex = assertThrows(PublicKeyResolutionFailedException::class.java) {
            resolver.extractPublicKey(createParsedDid())
        }
        assertTrue(ex.message!!.contains("network error"))
    }

    private fun createParsedDid() = ParsedDID(
        validDid,
        DidMethod.WEB,
        "example.com",
        validDid,
    )

    private fun mockDidDocument(
        verificationMaterial: Map<String, String> = emptyMap(),
        keyType: String = "Ed25519VerificationKey2020"
    ) {
        val publicKeyInfo: Map<String, String> =
            mapOf("id" to validDid, "type" to keyType) + verificationMaterial

        every {
            sendHTTPRequest(
                didJsonWellKnown,
                HttpMethod.GET
            )
        } returns didDocWithMethod(publicKeyInfo)
    }
}