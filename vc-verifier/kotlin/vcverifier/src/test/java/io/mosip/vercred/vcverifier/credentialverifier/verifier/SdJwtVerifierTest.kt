package io.mosip.vercred.vcverifier.credentialverifier.verifier

import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.Base64

class SdJwtVerifierTest{

    @Test
    fun `should verify sd-jwt successfully`() {

        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "sd-jwt_vc/sdJwt.txt")
        val vc = String(Files.readAllBytes(file.toPath()))

        assertTrue( SdJwtVerifier().verify(vc))
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
    fun `should throw exception for sd-jwt whose header carries no x5c`() {
        val missingCertificateException = assertThrows(IllegalArgumentException::class.java) {
            SdJwtVerifier().verify(sdJwtWithHeader("""{"alg":"ES256","typ":"vc+sd-jwt"}"""))
        }

        assertEquals("No X.509 certificate found in JWT header", missingCertificateException.message)
    }

    @Test
    fun `should throw exception for sd-jwt whose x5c is an empty chain`() {
        val emptyCertificateChainException = assertThrows(IllegalArgumentException::class.java) {
            SdJwtVerifier().verify(sdJwtWithHeader("""{"alg":"ES256","typ":"vc+sd-jwt","x5c":[]}"""))
        }

        assertEquals("No X.509 certificate found in JWT header", emptyCertificateChainException.message)
    }

    private fun sdJwtWithHeader(header: String): String {
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val payload = encoder.encodeToString("""{"iss":"https://issuer.example"}""".toByteArray())
        val signature = encoder.encodeToString(ByteArray(64))

        return "${encoder.encodeToString(header.toByteArray())}.$payload.$signature~"
    }
}