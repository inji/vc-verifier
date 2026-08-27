package io.mosip.vercred.vcverifier.keyResolver.types.jwks

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import io.mosip.vercred.vcverifier.utils.Util
import testutils.mapper
import testutils.readClasspathFile

class SdJwtVcIssuerMetadataResolverTest {

    private val resolver = SdJwtVcIssuerMetadataResolver()

    private val publicJwk = mapOf(
        "kid" to "signing-key-1",
        "kty" to "EC",
        "crv" to "P-256",
        "alg" to "ES256",
        "use" to "sig",
        "key_ops" to listOf("verify"),
        "x" to "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y" to "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
    )

    @BeforeEach
    fun setUp() {
        mockkObject(NetworkManagerClient.Companion)
    }

    @AfterEach
    fun tearDown() {
        clearAllMocks()
        unmockkAll()
    }

    private fun mockMetadata(url: String, response: Map<String, Any>?) {
        every { NetworkManagerClient.sendHTTPRequest(url, any()) } returns response
    }

    @Test
    fun `constructs metadata URI by inserting well-known path before issuer path`() {
        assertEquals(
            "https://issuer.example/.well-known/jwt-vc-issuer/tenant/123",
            resolver.metadataUriFor("https://issuer.example/tenant/123/").toString()
        )
    }

    @Test
    fun `constructs metadata URI for issuer without a path`() {
        assertEquals(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            resolver.metadataUriFor("https://issuer.example").toString()
        )
    }

    @Test
    fun `preserves explicit port and percent-encoded issuer path`() {
        assertEquals(
            "https://issuer.example:8443/.well-known/jwt-vc-issuer/a%20b",
            resolver.metadataUriFor("https://issuer.example:8443/a%20b").toString()
        )
    }

    @Test
    fun `resolves kid from issuer-bound inline JWKS`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf("issuer" to "https://issuer.example", "jwks" to mapOf("keys" to listOf(publicJwk)))
        )

        assertEquals(
            "EC",
            resolver.resolve("https://issuer.example", "signing-key-1", "ES256").algorithm
        )
    }

    @Test
    fun `resolves kid by following jwks_uri`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf("issuer" to "https://issuer.example", "jwks_uri" to "https://issuer.example/keys")
        )
        mockMetadata("https://issuer.example/keys", mapOf("keys" to listOf(publicJwk)))

        assertEquals(
            "EC",
            resolver.resolve("https://issuer.example", "signing-key-1", "ES256").algorithm
        )
    }

    @Test
    fun `rejects non-https jwks_uri`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf("issuer" to "https://issuer.example", "jwks_uri" to "http://issuer.example/keys")
        )

        val error = assertThrows(PublicKeyResolutionFailedException::class.java) {
            resolver.resolve("https://issuer.example", "signing-key-1", "ES256")
        }
        assertTrue(error.message!!.contains("'jwks_uri' must be an HTTPS URL"))
    }

    @Test
    fun `rejects metadata carrying both jwks and jwks_uri`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf(
                "issuer" to "https://issuer.example",
                "jwks" to mapOf("keys" to listOf(publicJwk)),
                "jwks_uri" to "https://issuer.example/keys"
            )
        )

        val error = assertThrows(PublicKeyResolutionFailedException::class.java) {
            resolver.resolve("https://issuer.example", "signing-key-1", "ES256")
        }
        assertTrue(error.message!!.contains("exactly one of 'jwks' or 'jwks_uri'"))
    }

    @Test
    fun `rejects metadata issuer substitution`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf("issuer" to "https://attacker.example", "jwks" to mapOf("keys" to listOf(publicJwk)))
        )

        val error = assertThrows(PublicKeyResolutionFailedException::class.java) {
            resolver.resolve("https://issuer.example", "signing-key-1", "ES256")
        }
        assertTrue(error.message!!.contains("exactly match"))
    }

    @Test
    fun `rejects ambiguous duplicate kid`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf(
                "issuer" to "https://issuer.example",
                "jwks" to mapOf("keys" to listOf(publicJwk, publicJwk))
            )
        )

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve("https://issuer.example", "signing-key-1", "ES256")
        }
        assertTrue(error.message!!.contains("Multiple keys"))
    }

    private val unlabelledEcJwk = publicJwk - "kid"

    private val unlabelledEd25519Jwk = mapOf(
        "kty" to "OKP",
        "crv" to "Ed25519",
        "x" to "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    )

    @Test
    fun `resolves the sole unlabelled key when the JWT kid matches nothing published`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf("issuer" to "https://issuer.example", "jwks" to mapOf("keys" to listOf(unlabelledEcJwk)))
        )

        assertEquals(
            "EC",
            resolver.resolve("https://issuer.example", "signing-key-1", "ES256").algorithm
        )
    }

    @Test
    fun `disambiguates unlabelled keys by the JWT algorithm`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf(
                "issuer" to "https://issuer.example",
                "jwks" to mapOf("keys" to listOf(unlabelledEd25519Jwk, unlabelledEcJwk))
            )
        )

        assertEquals(
            "EC",
            resolver.resolve("https://issuer.example", "signing-key-1", "ES256").algorithm
        )
    }

    @Test
    fun `rejects when several unlabelled keys suit the JWT algorithm`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf(
                "issuer" to "https://issuer.example",
                "jwks" to mapOf("keys" to listOf(unlabelledEcJwk, unlabelledEcJwk))
            )
        )

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve("https://issuer.example", "signing-key-1", "ES256")
        }
        assertEquals(
            "Cannot select between 2 usable keys in JWKS; " +
                "the issuer should publish a 'kid' for each key",
            error.message
        )
    }

    @Test
    fun `prefers an unlabelled key over one labelled with a different kid`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf(
                "issuer" to "https://issuer.example",
                "jwks" to mapOf(
                    "keys" to listOf(publicJwk + mapOf("kid" to "other-key"), unlabelledEcJwk)
                )
            )
        )

        assertEquals(
            "EC",
            resolver.resolve("https://issuer.example", "signing-key-1", "ES256").algorithm
        )
    }

    @Test
    fun `resolves a labelled key when the JWT carries no kid`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf("issuer" to "https://issuer.example", "jwks" to mapOf("keys" to listOf(publicJwk)))
        )

        assertEquals(
            "EC",
            resolver.resolve("https://issuer.example", null, "ES256").algorithm
        )
    }

    @Test
    fun `disambiguates labelled keys by algorithm when the JWT carries no kid`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf(
                "issuer" to "https://issuer.example",
                "jwks" to mapOf(
                    "keys" to listOf(
                        unlabelledEd25519Jwk + mapOf("kid" to "ed-key"),
                        publicJwk
                    )
                )
            )
        )

        assertEquals(
            "EC",
            resolver.resolve("https://issuer.example", null, "ES256").algorithm
        )
    }

    @Test
    fun `rejects when the JWT carries no kid and several labelled keys suit the algorithm`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf(
                "issuer" to "https://issuer.example",
                "jwks" to mapOf(
                    "keys" to listOf(publicJwk, publicJwk + mapOf("kid" to "signing-key-2"))
                )
            )
        )

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve("https://issuer.example", null, "ES256")
        }
        assertEquals(
            "Cannot select between 2 usable keys in JWKS; the JWT should carry a 'kid'",
            error.message
        )
    }

    @Test
    fun `reports why a sole unlabelled candidate cannot be used`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf(
                "issuer" to "https://issuer.example",
                "jwks" to mapOf("keys" to listOf(unlabelledEcJwk + mapOf("use" to "enc")))
            )
        )

        val error = assertThrows(PublicKeyResolutionFailedException::class.java) {
            resolver.resolve("https://issuer.example", "signing-key-1", "ES256")
        }
        assertEquals("JWK 'use' must be 'sig'", error.message)
    }

    @Test
    fun `reports the algorithm mismatch for a sole candidate when the JWT carries no kid`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf(
                "issuer" to "https://issuer.example",
                "jwks" to mapOf("keys" to listOf(unlabelledEd25519Jwk))
            )
        )

        val error = assertThrows(PublicKeyResolutionFailedException::class.java) {
            resolver.resolve("https://issuer.example", null, "ES256")
        }
        assertEquals("JWK 'kty' must be 'EC' for alg=ES256", error.message)
    }

    @Suppress("UNCHECKED_CAST")
    private fun fixture(name: String) =
        mapper.readValue(
            readClasspathFile("sd-jwt_vc/issuer_metadata/$name"), Map::class.java
        ) as Map<String, Any>

    @Test
    fun `resolves against real inline-JWKS metadata captured from a live issuer`() {
        val issuer = "https://demo.pid-issuer.bundesdruckerei.de/c"
        mockMetadata(
            "https://demo.pid-issuer.bundesdruckerei.de/.well-known/jwt-vc-issuer/c",
            fixture("metadataWithInlineJwks.json")
        )

        assertEquals("EC", resolver.resolve(issuer, null, "ES256").algorithm)
    }

    @Test
    fun `resolves against real jwks_uri metadata captured from a live issuer`() {
        val issuer = "https://trial.authlete.net"
        mockMetadata("$issuer/.well-known/jwt-vc-issuer", fixture("metadataWithJwksUri.json"))
        mockMetadata("$issuer/api/vci/jwks", fixture("jwksReferencedByJwksUri.json"))

        assertEquals(
            "EC",
            resolver.resolve(issuer, "ZYGIOHYuA9IpUijVwQNul3nE536x1JSWHiOfdS7sadg", "ES256").algorithm
        )
    }

    @Test
    fun `rejects unknown kid`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf("issuer" to "https://issuer.example", "jwks" to mapOf("keys" to listOf(publicJwk)))
        )

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve("https://issuer.example", "unknown-key", "ES256")
        }
        assertTrue(error.message!!.contains("No matching key found for kid=unknown-key"))
    }

    @Test
    fun `rejects algorithm confusion`() {
        mockMetadata(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            mapOf("issuer" to "https://issuer.example", "jwks" to mapOf("keys" to listOf(publicJwk)))
        )

        val error = assertThrows(PublicKeyResolutionFailedException::class.java) {
            resolver.resolve("https://issuer.example", "signing-key-1", "RS256")
        }
        assertTrue(error.message!!.contains("does not match"))
    }

    @Test
    fun `throws when metadata response is null`() {
        mockMetadata("https://issuer.example/.well-known/jwt-vc-issuer", null)

        assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve("https://issuer.example", "signing-key-1", "ES256")
        }
    }

    @Test
    fun `accepts an uppercase scheme and host and normalises them`() {
        assertEquals(
            "https://issuer.example/.well-known/jwt-vc-issuer/x",
            resolver.metadataUriFor("HTTPS://Issuer.Example/x").toString()
        )
    }

    @Test
    fun `rejects a malformed issuer URL without leaking URISyntaxException`() {
        val error = assertThrows(PublicKeyResolutionFailedException::class.java) {
            resolver.metadataUriFor("https://[bad")
        }
        assertTrue(error.message!!.contains("must be an HTTPS URL"))
    }

    @Test
    fun `rejects issuer URLs unsafe for metadata discovery`() {
        listOf(
            "http://issuer.example",
            "https://user@issuer.example",
            "https://issuer.example/path?query=value",
            "https://issuer.example/path#fragment",
            "urn:uuid:8d8ac610-566d-4ef0-9c22-186b2a5ed793",
            "ftp://issuer.example",
            "issuer.example"
        ).forEach { issuer ->
            assertThrows(PublicKeyResolutionFailedException::class.java) {
                resolver.metadataUriFor(issuer)
            }
        }
    }

    /**
     * The credential in this fixture carries an `x5c` certificate whose public key is byte-identical
     * to the key its issuer publishes as metadata, so the same signature verifies through either
     * mechanism. That makes it the only cover for a metadata-resolved key against a signature we did
     * not produce ourselves.
     *
     * It deliberately bypasses [io.mosip.vercred.vcverifier.credentialverifier.verifier.SdJwtVerifier],
     * which resolves this credential through its certificate instead — `x5c` takes precedence in the
     * dispatch. Verifying the metadata mechanism end to end needs a credential carrying `kid` and no
     * `x5c`, which no issuer surveyed produces. Should the mechanism-precedence question in
     * draft-ietf-oauth-sd-jwt-vc-10 10.2 be resolved in favour of the mechanism `iss` designates,
     * this becomes that end-to-end test unchanged.
     */
    @Test
    fun `resolves a key that verifies a real issuer's signature`() {
        val issuer = "https://demo-issuer.wwwallet.org/openid"
        mockMetadata(
            "https://demo-issuer.wwwallet.org/.well-known/jwt-vc-issuer/openid",
            fixture("metadataMatchingCredentialX5c.json")
        )
        val issuerSignedJwt = readClasspathFile("sd-jwt_vc/sdJwtVcResolvableByX5cAndKid.txt")
            .trim().split("~").first()

        val publicKey = resolver.resolve(issuer, "8636af04-5796-4f46-a73e-d690d7d4e7f3", "ES256")

        assertTrue(Util.verifyJwt(issuerSignedJwt, publicKey, "ES256"))
    }
}
