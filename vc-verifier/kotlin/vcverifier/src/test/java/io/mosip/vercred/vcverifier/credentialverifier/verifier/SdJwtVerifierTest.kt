package io.mosip.vercred.vcverifier.credentialverifier.verifier

import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.util.ResourceUtils
import java.nio.file.Files

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
}