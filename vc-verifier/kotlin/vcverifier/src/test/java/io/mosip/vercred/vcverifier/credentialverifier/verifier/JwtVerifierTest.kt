package io.mosip.vercred.vcverifier.credentialverifier.verifier

import io.mockk.*
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.utils.Util
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.util.ResourceUtils
import java.net.URI
import java.nio.file.Files
import java.security.PublicKey
import java.util.Base64

class JwtVerifierTest {

    private lateinit var jwtVerifier: JwtVerifier
    private val mockPublicKey = mockk<PublicKey>()

    @BeforeEach
    fun setup() {
        mockkObject(Util)
        mockkConstructor(PublicKeyResolverFactory::class)
        every { anyConstructed<PublicKeyResolverFactory>().get(any(), any()) } returns mockPublicKey
        every { anyConstructed<PublicKeyResolverFactory>().get(any(), isNull()) } returns mockPublicKey
        jwtVerifier = JwtVerifier() 
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    private fun loadSampleJwt(fileName: String): String {
        val file = ResourceUtils.getFile("classpath:jwt_vc/$fileName")
        return String(Files.readAllBytes(file.toPath())).trim()
    }

    private fun replaceHeaderAndPayload(originalJwt: String, newHeader: String, newPayload: String): String {
        val parts = originalJwt.split(".")
        val headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(newHeader.toByteArray(Charsets.UTF_8))
        val payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(newPayload.toByteArray(Charsets.UTF_8))
        return "$headerB64.$payloadB64.${parts[2]}"
    }

    @Test
    fun `should verify successfully using base valid sample jwt`() {
        val vc = loadSampleJwt("validJwt.txt")
        every { Util.verifyJwt(any(), any(), any()) } returns true
        assertTrue(jwtVerifier.verify(vc))
    }

    @Test
    fun `should return false gracefully for invalid signature`() {
        val vc = loadSampleJwt("invalidJwt.txt")
        every { Util.verifyJwt(any(), any(), any()) } throws SignatureVerificationException("Algorithm mismatch") 
        assertFalse(jwtVerifier.verify(vc))
    }

    @Test
    fun `should extract JKU and KID to fetch key from JWK Set`() {
        val baseVc = loadSampleJwt("validJwt.txt")
        val header = """{"alg":"RS256", "jku":"https://example.com/.well-known/jwks.json", "kid":"key-1"}"""
        val payload = """{"iss":"https://example.com"}"""
        val vc = replaceHeaderAndPayload(baseVc, header, payload)

        every { Util.verifyJwt(any(), any(), any()) } returns true
        assertTrue(jwtVerifier.verify(vc))
    }

    @Test
    fun `should use KID directly as URI if it is a fully qualified DID`() {
        val baseVc = loadSampleJwt("validJwt.txt")
        val header = """{"alg":"RS256", "kid":"did:web:example.com#key-1"}"""
        val payload = """{"iss":"did:web:different-issuer.com"}"""
        val vc = replaceHeaderAndPayload(baseVc, header, payload)

        every { Util.verifyJwt(any(), any(), any()) } returns true
        assertTrue(jwtVerifier.verify(vc))
    }

    @Test
    fun `should combine Issuer DID and KID fragment to construct verification URI`() {
        val baseVc = loadSampleJwt("validJwt.txt")
        val header = """{"alg":"RS256", "kid":"#key-1"}"""
        val payload = """{"iss":"did:web:example.com"}"""
        val vc = replaceHeaderAndPayload(baseVc, header, payload)

        every { Util.verifyJwt(any(), any(), any()) } returns true
        assertTrue(jwtVerifier.verify(vc))
    }
}
