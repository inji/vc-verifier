package io.mosip.vercred.vcverifier.credentialverifier.verifier

import io.mockk.clearMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.verify
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import testutils.mockHttpResponse
import testutils.readClasspathFile
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import org.junit.jupiter.api.assertThrows
import org.springframework.util.ResourceUtils
import java.nio.file.Files


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CwtVerifierTest {

    // x5u fixtures are signed for https://issuer.example.com; the cert fetch goes through the mocked NetworkManagerClient.
    private val x5uCertUrl = "https://issuer.example.com/leaf-cert.der"
    private val x5tX5uCertUrl = "https://issuer.example.com/x5t-x5u-leaf-cert.der"

    @BeforeAll
    fun setup() {
        mockkObject(NetworkManagerClient.Companion)
        loadMockPublicKeys()
        val certBytes = Files.readAllBytes(
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "cwt_vc/x5u-leaf-cert.der").toPath()
        )
        every { NetworkManagerClient.sendHTTPRequestForBytes(x5uCertUrl) } returns certBytes
        val x5tCertBytes = Files.readAllBytes(
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "cwt_vc/x5t-x5u-leaf-cert.der").toPath()
        )
        every { NetworkManagerClient.sendHTTPRequestForBytes(x5tX5uCertUrl) } returns x5tCertBytes
        val expiredCertBytes = Files.readAllBytes(
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "cwt_vc/x5u-expired-cert.der").toPath()
        )
        every { NetworkManagerClient.sendHTTPRequestForBytes("https://issuer.example.com/x5u-expired-cert.der") } returns expiredCertBytes
    }

    @Test
    fun `should verify valid CWT via x5u COSE header`() {
        val coseHex = readClasspathFile("cwt_vc/valid-x5u-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertTrue(CwtVerifier().verify(coseHex))
    }

    @Test
    fun `should fail when x5u-resolved CWT has wrong signature`() {
        val coseHex = readClasspathFile("cwt_vc/invalid-x5u-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertThrows<SignatureVerificationException> {
            CwtVerifier().verify(coseHex)
        }
    }

    @Test
    fun `should reject x5u whose host differs from iss host`() {
        val coseHex = readClasspathFile("cwt_vc/mismatched-host-x5u-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertThrows<PublicKeyNotFoundException> {
            CwtVerifier().verify(coseHex)
        }
    }

    @Test
    fun `should reject non-https x5u`() {
        val coseHex = readClasspathFile("cwt_vc/http-x5u-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertThrows<PublicKeyNotFoundException> {
            CwtVerifier().verify(coseHex)
        }
    }

    @Test
    fun `should ignore x5u carried only in the unprotected header`() {
        // Earlier tests already hit sendHTTPRequestForBytes, so wipe the call history (keep stubs) before counting.
        clearMocks(NetworkManagerClient.Companion, answers = false)
        every {
            NetworkManagerClient.sendHTTPRequest("https://issuer.example.com/.well-known/jwks.json", any())
        } returns null
        val coseHex = readClasspathFile("cwt_vc/unprotected-x5u-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertThrows<PublicKeyNotFoundException> {
            CwtVerifier().verify(coseHex)
        }
        verify(exactly = 0) { NetworkManagerClient.sendHTTPRequestForBytes(x5uCertUrl) }
    }

    @Test
    fun `should verify CWT with unprotected x5u when protected x5t matches the certificate`() {
        val coseHex = readClasspathFile("cwt_vc/unprotected-x5u-protected-x5t-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertTrue(CwtVerifier().verify(coseHex))
    }

    @Test
    fun `should reject unprotected x5u when protected x5t does not match the certificate`() {
        val coseHex = readClasspathFile("cwt_vc/unprotected-x5u-mismatched-x5t-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertThrows<PublicKeyNotFoundException> {
            CwtVerifier().verify(coseHex)
        }
    }

    @Test
    fun `should reject protected x5u that is an integer`() {
        assertMalformedX5uRejected("invalid-x5u-protected-int-cwt.hex")
    }

    @Test
    fun `should reject protected x5u that is a boolean`() {
        assertMalformedX5uRejected("invalid-x5u-protected-bool-cwt.hex")
    }

    @Test
    fun `should reject x5u certificate that is expired`() {
        assertThrows<PublicKeyNotFoundException> { CwtVerifier().verify(readFixture("x5u-expired-cwt.hex")) }
    }

    @Test
    fun `should verify valid EC signed CWT`() {
        val coseHex = readClasspathFile("cwt_vc/valid-ec-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertTrue(CwtVerifier().verify(coseHex))
    }

    @Test
    fun `should fail when EC CWT is verified with wrong public key`() {


        val coseHex = readClasspathFile("cwt_vc/invalid-ec-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertThrows<SignatureVerificationException> {
            CwtVerifier().verify(coseHex)
        }

    }


    private fun readFixture(name: String) = readClasspathFile("cwt_vc/$name").replace("\\s".toRegex(), "")

    // The stubbed fallback JWKS URL must never be requested for a malformed x5u.
    private fun assertMalformedX5uRejected(fixture: String) {
        val jwksUrl = "https://issuer.example.com/.well-known/jwks.json"
        clearMocks(NetworkManagerClient.Companion, answers = false)
        every { NetworkManagerClient.sendHTTPRequest(jwksUrl, any()) } returns null

        assertThrows<SignatureVerificationException> { CwtVerifier().verify(readFixture(fixture)) }
        verify(exactly = 0) { NetworkManagerClient.sendHTTPRequest(jwksUrl, any()) }
    }

    private fun loadMockPublicKeys() {
        mockHttpResponse("https://221f38cc3ffc.ngrok-free.app/v1/certify/.well-known/jwks.json", readClasspathFile("cwt_vc/public_key/jwksECkey.json"))
        mockHttpResponse("https://9c65dc69fafc.ngrok-free.app/v1/certify/.well-known/jwks.json", readClasspathFile("cwt_vc/public_key/jwksinvalidECkey.json"))
    }
}