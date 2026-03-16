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

}