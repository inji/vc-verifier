package io.mosip.vercred.vcverifier.credentialverifier.verifier

import io.mockk.*
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidJwkPublicKeyResolver
import io.mosip.vercred.vcverifier.constants.DidMethod
import io.mosip.vercred.vcverifier.keyResolver.types.did.ParsedDID
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.net.URI
import org.json.JSONObject
import java.util.Base64

class JwtVerifierTest {

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    private fun loadSampleJwt(fileName: String): String {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "jwt_vc/$fileName")
        return String(Files.readAllBytes(file.toPath())).trim()
    }

    @Test
    fun `should verify jwt successfully`() {
        val vc = loadSampleJwt("validJwt.txt")

        val payloadBase64 = vc.split(".")[1]
        val payloadJson = JSONObject(String(Base64.getUrlDecoder().decode(payloadBase64)))
        val issuer = payloadJson.getString("iss")

        val resolver = DidJwkPublicKeyResolver()
        val parsedDid = ParsedDID(issuer, DidMethod.JWK, issuer.removePrefix("did:jwk:"), issuer)
        val realPublicKey = resolver.extractPublicKey(parsedDid)

        mockkConstructor(PublicKeyResolverFactory::class)
        every { anyConstructed<PublicKeyResolverFactory>().get(any()) } returns realPublicKey

        assertTrue(JwtVerifier().verify(vc))
    }

    @Test
    fun `should throw for tampered jwt`() {
        val validVc = loadSampleJwt("validJwt.txt") 
        val invalidVc = loadSampleJwt("invalidJwt.txt")

        // Using real key from valid JWT to genuinely test signature rejection
        val payloadBase64 = validVc.split(".")[1]
        val payloadJson = JSONObject(String(Base64.getUrlDecoder().decode(payloadBase64)))
        val issuer = payloadJson.getString("iss")
        val realPublicKey = DidJwkPublicKeyResolver().extractPublicKey(
            ParsedDID(issuer, DidMethod.JWK, issuer.removePrefix("did:jwk:"), issuer)
        )

        mockkConstructor(PublicKeyResolverFactory::class)
        every { anyConstructed<PublicKeyResolverFactory>().get(any()) } returns realPublicKey

        assertThrows(Exception::class.java) {
            JwtVerifier().verify(invalidVc)
        }
    }
}
