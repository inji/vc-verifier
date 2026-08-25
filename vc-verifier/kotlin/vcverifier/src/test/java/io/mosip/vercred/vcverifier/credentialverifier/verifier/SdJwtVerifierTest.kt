package io.mosip.vercred.vcverifier.credentialverifier.verifier

import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import io.mockk.*
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.security.PublicKey
import java.util.Base64

class SdJwtVerifierTest{

    @Test
    fun `should verify sd-jwt successfully`() {

        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "sd-jwt_vc/sdJwt.txt")
        val vc = String(Files.readAllBytes(file.toPath()))

        assertTrue( SdJwtVerifier().verify(vc))
    }

    @Test
    fun `should verify a real dc+sd-jwt successfully with x5c`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "sd-jwt_vc/sdJwtVcWithX5cSanMatchingIss.txt")
        val vc = String(Files.readAllBytes(file.toPath())).trim()

        assertTrue(SdJwtVerifier().verify(vc))
    }

    @Test
    fun `should verify a real dc+sd-jwt whose kid is a did-key`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "sd-jwt_vc/sdJwtVcWithDidKeyIssuer.txt")
        val vc = String(Files.readAllBytes(file.toPath())).trim()

        assertTrue(SdJwtVerifier().verify(vc))
    }

    @Test
    fun `should return false for tampered sd-jwt`() {

        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "sd-jwt_vc/invalidSdJwt.txt")
        val vc = String(Files.readAllBytes(file.toPath()))

        assertFalse( SdJwtVerifier().verify(vc))
    }

    @Test
    fun `should throw exception for mso_mdoc status check as its not supported`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "sd-jwt_vc/sdJwt.txt")
        val vc = String(Files.readAllBytes(file.toPath()))
        val unsupportedStatusCheckException = assertThrows(UnsupportedOperationException::class.java) {
            MsoMdocVerifiableCredential().checkStatus(vc, null)
        }

        assertEquals("Credential status checking not supported for this credential format",unsupportedStatusCheckException.message)
    }

    @Test
    fun `should fall back to issuer resolution when the header carries no x5c`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SdJwtVerifier().verify(
                sdJwtWithHeader("""{"alg":"ES256","typ":"vc+sd-jwt"}""", """{"iss":"urn:issuer"}""")
            )
        }

        assertEquals("JWT 'iss' must be a DID or an HTTPS URL to resolve the issuer key", error.message)
    }

    @Test
    fun `should fall back to issuer resolution when x5c is an empty chain`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SdJwtVerifier().verify(
                sdJwtWithHeader(
                    """{"alg":"ES256","typ":"vc+sd-jwt","x5c":[]}""",
                    """{"iss":"urn:issuer"}"""
                )
            )
        }

        assertEquals("JWT 'iss' must be a DID or an HTTPS URL to resolve the issuer key", error.message)
    }

    @Test
    fun `should require an iss claim when the header carries no x5c`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SdJwtVerifier().verify(sdJwtWithHeader("""{"alg":"ES256","typ":"vc+sd-jwt"}""", "{}"))
        }

        assertEquals(
            "JWT 'iss' claim is required when no 'x5c' is present in the JWT header",
            error.message
        )
    }

    @Test
    fun `should resolve an https issuer key when the JWT carries no kid`() {
        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://issuer.example/.well-known/jwt-vc-issuer",
                any()
            )
        } returns mapOf(
            "issuer" to "https://issuer.example",
            "jwks" to mapOf(
                "keys" to listOf(
                    mapOf(
                        "kty" to "EC",
                        "crv" to "P-256",
                        "x" to "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                        "y" to "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
                    )
                )
            )
        )

        assertEquals(
            "EC",
            SdJwtVerifier().resolvePublicKeyFromIssuer("https://issuer.example", null, "ES256").algorithm
        )
    }

    @Test
    fun `should require a kid when resolving the issuer key from a DID`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SdJwtVerifier().resolvePublicKeyFromIssuer("did:web:issuer.example", null, "ES256")
        }

        assertEquals("JWT 'kid' is required when resolving the issuer key from a DID", error.message)
    }

    @Test
    fun `should resolve relative DID kid only against issuer DID`() {
        val publicKey = mockk<PublicKey>()
        mockkConstructor(DidPublicKeyResolver::class)
        every { anyConstructed<DidPublicKeyResolver>().resolve("did:web:issuer.example#key-1", null) } returns publicKey

        assertEquals(
            publicKey,
            SdJwtVerifier().resolvePublicKeyFromIssuer("did:web:issuer.example", "#key-1", "ES256")
        )
    }

    @Test
    fun `should reject DID kid controlled by a different issuer`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SdJwtVerifier().resolvePublicKeyFromIssuer(
                "did:web:issuer.example",
                "did:web:attacker.example#key-1",
                "ES256"
            )
        }

        assertEquals(
            "JWT 'kid' must be a fragment or an absolute DID URL controlled by JWT 'iss'",
            error.message
        )
    }

    @Test
    fun `should resolve https issuer kid through JWT VC issuer metadata`() {
        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://issuer.example/.well-known/jwt-vc-issuer",
                any()
            )
        } returns mapOf(
            "issuer" to "https://issuer.example",
            "jwks" to mapOf(
                "keys" to listOf(
                    mapOf(
                        "kid" to "signing-key-1",
                        "kty" to "EC",
                        "crv" to "P-256",
                        "x" to "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                        "y" to "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
                    )
                )
            )
        )

        assertEquals(
            "EC",
            SdJwtVerifier().resolvePublicKeyFromIssuer("https://issuer.example", "signing-key-1", "ES256").algorithm
        )
    }

    @Test
    fun `should not dereference a DID in kid when iss is an HTTPS URL`() {
        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://issuer.example/.well-known/jwt-vc-issuer", any(), any(), any(), any(), any()
            )
        } returns mapOf(
            "issuer" to "https://issuer.example",
            "jwks" to mapOf(
                "keys" to listOf(
                    mapOf(
                        "kid" to "signing-key-1",
                        "kty" to "EC", "crv" to "P-256",
                        "x" to "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                        "y" to "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
                    )
                )
            )
        )
        mockkConstructor(DidPublicKeyResolver::class)

        // The mechanism is chosen by 'iss' alone, so a DID in 'kid' is only ever a JWK Set lookup
        // string. Dereferencing it would let a credential pick the verification process for an
        // issuer, which draft-ietf-oauth-sd-jwt-vc-10 10.2 forbids.
        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            SdJwtVerifier().resolvePublicKeyFromIssuer(
                "https://issuer.example", "did:web:attacker.example#key-1", "ES256"
            )
        }

        assertEquals("No matching key found for kid=did:web:attacker.example#key-1", error.message)
        verify(exactly = 0) { anyConstructed<DidPublicKeyResolver>().resolve(any(), any()) }
    }

    @Test
    fun `should reject unknown DID methods for the issuer key`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SdJwtVerifier().resolvePublicKeyFromIssuer("did:ion:EiClaZ", "#key-1", "ES256")
        }

        assertEquals(
            "JWT 'iss' DID method is not supported for issuer keys. " +
                "Supported: did:web, did:key, did:jwk",
            error.message
        )
    }

    @Test
    fun `should reject a kid whose iss is neither a DID nor an HTTPS URL`() {
        listOf(
            "urn:uuid:8d8ac610-566d-4ef0-9c22-186b2a5ed793",
            "http://issuer.example",
            "ftp://issuer.example",
            "issuer.example",
            ""
        ).forEach { issuer ->
            val error = assertThrows(IllegalArgumentException::class.java) {
                SdJwtVerifier().resolvePublicKeyFromIssuer(issuer, "signing-key-1", "ES256")
            }

            assertEquals(
                "JWT 'iss' must be a DID or an HTTPS URL to resolve the issuer key",
                error.message
            )
        }
    }

    @AfterEach
    fun tearDown() {
        clearAllMocks()
        unmockkAll()
    }

    private fun sdJwtWithHeader(
        header: String,
        payloadJson: String = """{"iss":"https://issuer.example"}"""
    ): String {
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val payload = encoder.encodeToString(payloadJson.toByteArray())
        val signature = encoder.encodeToString(ByteArray(64))

        return "${encoder.encodeToString(header.toByteArray())}.$payload.$signature~"
    }
}
