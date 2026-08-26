package io.mosip.vercred.vcverifier.keyResolver.types.jwks

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class JwksPublicKeyResolverTest {

    private val uri = "https://issuer.example/jwks.json"
    private val resolver = JwksPublicKeyResolver()

    private val publicJwk = mapOf(
        "kid" to "signing-key-1",
        "kty" to "EC",
        "crv" to "P-256",
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

    private fun mockJwks(vararg keys: Map<String, Any>) {
        every { NetworkManagerClient.sendHTTPRequest(uri, any()) } returns mapOf("keys" to keys.toList())
    }

    @Test
    fun `resolves the key matching the requested kid`() {
        val otherKey = publicJwk + mapOf("kid" to "signing-key-2")
        mockJwks(publicJwk, otherKey)

        assertEquals("EC", resolver.resolve(uri, "signing-key-1").algorithm)
    }

    @Test
    fun `resolves the only published key when no kid is supplied`() {
        mockJwks(publicJwk)

        assertEquals("EC", resolver.resolve(uri, null).algorithm)
    }

    @Test
    fun `throws when no kid is supplied and the set is ambiguous`() {
        mockJwks(publicJwk, publicJwk + mapOf("kid" to "signing-key-2"))

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(uri, null)
        }

        assertTrue(error.message!!.contains("Cannot select between 2 usable keys"))
    }

    @Test
    fun `resolves an unlabelled key when the kid matches nothing labelled`() {
        mockJwks(publicJwk - "kid")

        assertEquals("EC", resolver.resolve(uri, "signing-key-1").algorithm)
    }

    @Test
    fun `does not borrow a key labelled with a different kid`() {
        mockJwks(publicJwk + mapOf("kid" to "signing-key-2"))

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(uri, "signing-key-1")
        }

        assertEquals("No matching key found for kid=signing-key-1", error.message)
    }

    @Test
    fun `throws when no key matches the kid`() {
        mockJwks(publicJwk)

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(uri, "unknown-key")
        }

        assertEquals("No matching key found for kid=unknown-key", error.message)
    }

    @Test
    fun `throws when more than one key matches the kid`() {
        mockJwks(publicJwk, publicJwk)

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(uri, "signing-key-1")
        }

        assertEquals("Multiple keys found for kid=signing-key-1", error.message)
    }

    @Test
    fun `throws when the keys array is missing`() {
        every { NetworkManagerClient.sendHTTPRequest(uri, any()) } returns mapOf("issuer" to "https://issuer.example")

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(uri, "signing-key-1")
        }

        assertEquals("JWKS 'keys' array not found", error.message)
    }

    @Test
    fun `throws when the response is null`() {
        every { NetworkManagerClient.sendHTTPRequest(uri, any()) } returns null

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(uri, "signing-key-1")
        }

        assertEquals("JWKS response is null", error.message)
    }

    @Test
    fun `rejects a key published for encryption`() {
        mockJwks(publicJwk + mapOf("use" to "enc"))

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(uri, "signing-key-1")
        }

        assertTrue(error.message!!.contains("JWK 'use' must be 'sig'"))
    }

    @Test
    fun `rejects a key whose key_ops does not permit verify`() {
        mockJwks(publicJwk + mapOf("key_ops" to listOf("encrypt")))

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(uri, "signing-key-1")
        }

        assertTrue(error.message!!.contains("JWK 'key_ops' must permit 'verify'"))
    }

    @Test
    fun `rejects a key whose key_ops is a scalar rather than an array`() {
        mockJwks(publicJwk + mapOf("key_ops" to "encrypt"))

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(uri, "signing-key-1")
        }

        assertTrue(error.message!!.contains("JWK 'key_ops' must be an array of strings"))
    }

    @Test
    fun `rejects a key whose key_ops array holds a non-string`() {
        mockJwks(publicJwk + mapOf("key_ops" to listOf("verify", 42)))

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(uri, "signing-key-1")
        }

        assertTrue(error.message!!.contains("JWK 'key_ops' must be an array of strings"))
    }

    @Test
    fun `rejects a JWK carrying private key material`() {
        mockJwks(publicJwk + mapOf("d" to "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"))

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(uri, "signing-key-1")
        }

        assertTrue(error.message!!.contains("JWK must not contain private key material"))
    }

    @Test
    fun `throws when kty is missing`() {
        mockJwks(publicJwk - "kty")

        val error = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(uri, "signing-key-1")
        }

        assertEquals("Missing 'kty' in JWK", error.message)
    }
}
