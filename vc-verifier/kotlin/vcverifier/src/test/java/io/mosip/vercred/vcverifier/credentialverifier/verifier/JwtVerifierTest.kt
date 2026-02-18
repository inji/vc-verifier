package io.mosip.vercred.vcverifier.credentialverifier.verifier

import io.mockk.*
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.utils.Util
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.security.PublicKey

class JwtVerifierTest {

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    private fun loadSampleJwt(fileName: String): String {
        val file = ResourceUtils.getFile("classpath:jwt_vc/$fileName")
        return String(Files.readAllBytes(file.toPath())).trim()
    }

    @Test
    fun `should verify successfully by prioritizing kid from header`() {
        val vc = loadSampleJwt("validJwt.txt")
        val mockPublicKey = mockk<PublicKey>()

        mockkObject(Util)
        every { Util.verifyJwt(any(), any(), any()) } returns true

        mockkConstructor(PublicKeyResolverFactory::class)
        every { anyConstructed<PublicKeyResolverFactory>().get(any()) } returns mockPublicKey

        assertTrue(JwtVerifier().verify(vc))
    }

    @Test
    fun `should throw SecurityException for invalid signature`() {
        val vc = loadSampleJwt("invalidJwt.txt")
        mockkObject(Util)
        every { Util.verifyJwt(any(), any(), any()) } returns false // Trigger exception

        mockkConstructor(PublicKeyResolverFactory::class)
        every { anyConstructed<PublicKeyResolverFactory>().get(any()) } returns mockk<PublicKey>()

        assertThrows(SecurityException::class.java) {
            JwtVerifier().verify(vc)
        }
    }
}
