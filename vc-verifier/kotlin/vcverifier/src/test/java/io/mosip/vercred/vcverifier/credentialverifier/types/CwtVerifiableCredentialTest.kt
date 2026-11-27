package io.mosip.vercred.vcverifier.credentialverifier.types

import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifierFactory
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.springframework.util.ResourceUtils
import testutils.mockHttpResponse
import testutils.readClasspathFile
import java.nio.file.Files

// End-to-end test of the production CWT flow (CredentialVerifierFactory → CwtVerifiableCredential), executing validate() and verify() together for both key-resolution paths
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CwtVerifiableCredentialTest {

    private val credential = CredentialVerifierFactory().get(CredentialFormat.CWT_VC)

    @BeforeAll
    fun setup() {
        mockkObject(NetworkManagerClient.Companion)
        mockHttpResponse(
            "https://221f38cc3ffc.ngrok-free.app/v1/certify/.well-known/jwks.json",
            readClasspathFile("cwt_vc/public_key/jwksECkey.json")
        )

        val certBytes = Files.readAllBytes(
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "cwt_vc/x5u-leaf-cert.der").toPath()
        )
        every { NetworkManagerClient.sendHTTPRequestForBytes("https://issuer.example.com/leaf-cert.der") } returns certBytes
    }

    @Test
    fun `end-to-end via JWKS fallback - validate then verify succeed`() {
        val coseHex = readClasspathFile("cwt_vc/valid-ec-cwt.hex").replace("\\s".toRegex(), "")

        val validationStatus = credential.validate(coseHex)
        assertEquals("", validationStatus.validationErrorCode, "validate() should pass before verify() runs")

        assertTrue(credential.verify(coseHex))
    }

    @Test
    fun `end-to-end via x5u - validate then verify succeed`() {
        val coseHex = readClasspathFile("cwt_vc/valid-x5u-cwt.hex").replace("\\s".toRegex(), "")

        val validationStatus = credential.validate(coseHex)
        assertEquals("", validationStatus.validationErrorCode, "validate() should pass before verify() runs")

        assertTrue(credential.verify(coseHex))
    }
}