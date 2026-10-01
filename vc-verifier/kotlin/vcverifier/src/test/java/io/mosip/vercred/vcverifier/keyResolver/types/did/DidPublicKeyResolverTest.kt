package io.mosip.vercred.vcverifier.keyResolver.types.did

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import io.mockk.verify
import io.mosip.vercred.vcverifier.constants.DidMethod
import io.mosip.vercred.vcverifier.testHelpers.validDidJwk
import io.mosip.vercred.vcverifier.testHelpers.validDidWeb
import io.mosip.vercred.vcverifier.testHelpers.validEdDidKey
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.util.Base64

class DidPublicKeyResolverTest {
    @BeforeEach
    fun setUp() {
        mockkConstructor(DidJwkPublicKeyResolver::class)
        mockkConstructor(DidKeyPublicKeyResolver::class)
        mockkConstructor(DidWebPublicKeyResolver::class)
    }

    @AfterEach
    fun tearDown() {
        clearAllMocks()
        unmockkAll()
    }

    @Test
    fun `should call Did Jwk resolver when the input did is of method type jwk`() {
        val didPublicKeyResolver = DidPublicKeyResolver()
        every {
            anyConstructed<DidJwkPublicKeyResolver>().extractPublicKey(
                any(),
                any()
            )
        } returns mockk()


        didPublicKeyResolver.resolve(validDidJwk)

        verify(exactly = 1) {
            anyConstructed<DidJwkPublicKeyResolver>().extractPublicKey(any(), any())
        }
    }

    @Test
    fun `should call Did Key resolver when the input did is of method type key`() {
        val didPublicKeyResolver = DidPublicKeyResolver()
        every {
            anyConstructed<DidKeyPublicKeyResolver>().extractPublicKey(
                any(),
                any()
            )
        } returns mockk()


        didPublicKeyResolver.resolve(validEdDidKey)

        verify(exactly = 1) {
            anyConstructed<DidKeyPublicKeyResolver>().extractPublicKey(
                ParsedDID(
                    did = validEdDidKey,
                    method = DidMethod.KEY,
                    id = validEdDidKey.split("did:key:")[1],
                    didUrl = validEdDidKey
                ), null
            )
        }
    }

    @Test
    fun `should call Did web resolver when the input did is of method type web`() {
         val validDid = "$validDidWeb#key-1"
        val didPublicKeyResolver = DidPublicKeyResolver()
        every {
            anyConstructed<DidWebPublicKeyResolver>().extractPublicKey(
                any(),
                any()
            )
        } returns mockk()

        didPublicKeyResolver.resolve(validDid)

        verify(exactly = 1) {
            anyConstructed<DidWebPublicKeyResolver>().extractPublicKey(
                ParsedDID(
                    did = validDidWeb,
                    method = DidMethod.WEB,
                    id = "example.com",
                    didUrl = validDid,
                    fragment = "key-1"
                ), null
            )
        }
    }

    //test without mocking
    @Test
    fun `should successfully resolve did with method type jwk`() {
        unmockkAll()
        val validDid = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImlydDktbTFubUtyM0dhTXlKTEdGV0ZscUd6UlJjSnV3TEtxTFlTQWJWdFkiLCJ5IjoiNXhMeGNKeDg2UEdvZDFnTzRadThvY29iR3hNNXRnMi13NVc5ZEFaQk5kQSIsInVzZSI6InNpZyJ9#0"
        val didPublicKeyResolver = DidPublicKeyResolver()

        val publicKey = didPublicKeyResolver.resolve(validDid)

        assertEquals("EC",publicKey.algorithm)
    }

    @Test
    fun `should resolve did jwk with base64url padding to the same key as without padding`() {
        unmockkAll()
        val jwk = """{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","kid":"1"}"""
        val paddedId = Base64.getUrlEncoder().encodeToString(jwk.toByteArray())
        val unpaddedId = Base64.getUrlEncoder().withoutPadding().encodeToString(jwk.toByteArray())
        assertTrue(paddedId.endsWith("=="))
        val didPublicKeyResolver = DidPublicKeyResolver()

        val paddedKey = didPublicKeyResolver.resolve("did:jwk:$paddedId")
        val paddedKeyWithFragment = didPublicKeyResolver.resolve("did:jwk:$paddedId#0")
        val unpaddedKey = didPublicKeyResolver.resolve("did:jwk:$unpaddedId#0")

        assertArrayEquals(unpaddedKey.encoded, paddedKey.encoded)
        assertArrayEquals(unpaddedKey.encoded, paddedKeyWithFragment.encoded)
    }

}