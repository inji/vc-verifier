package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mosip.vercred.vcverifier.CredentialsVerifier
import io.mosip.vercred.vcverifier.constants.CredentialFormat.MSO_MDOC
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PURPOSE_REVOCATION
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PURPOSE_SUSPENSION
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.data.CredentialVerificationSummary
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.testHelpers.MdocStatusListFixtures.STATUS_URI
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.util.ResourceUtils
import testutils.mockHttpBytesResponse
import java.nio.file.Files

class MdocStatusListFixtureFileTest {

    private val verifier = CredentialsVerifier()
    private val mdocWithStatus = readText("mso_mdoc/status/mdoc_with_status")

    @BeforeEach
    fun setup() {
        mockkObject(NetworkManagerClient.Companion)
    }

    @AfterEach
    fun teardown() {
        unmockkObject(NetworkManagerClient.Companion)
    }

    @Test
    fun `resource VALID CWT maps to revocation only`() {
        val result = verifyWith("statuslist_valid.cwt")
        assertTrue(result.verificationResult.verificationStatus)
        assertRevocationOnlyPassing(result.credentialStatus)
    }

    @Test
    fun `resource INVALID CWT maps to INVALID`() {
        val result = verifyWith("statuslist_invalid.cwt")
        assertFalse(result.credentialStatus.getValue(STATUS_PURPOSE_REVOCATION).isValid)
    }

    @Test
    fun `resource SUSPENDED CWT maps to SUSPENDED`() {
        val result = verifyWith("statuslist_suspended.cwt")
        assertFalse(result.credentialStatus.getValue(STATUS_PURPOSE_SUSPENSION).isValid)
    }

    @Test
    fun `resource bits2 VALID CWT maps to revocation and suspension`() {
        val result = verifyWith("statuslist_bits2_valid.cwt")
        assertPassingStatus(result.credentialStatus)
    }

    @Test
    fun `resource bits2 INVALID CWT maps to INVALID`() {
        val result = verifyWith("statuslist_bits2_invalid.cwt")
        assertFalse(result.credentialStatus.getValue(STATUS_PURPOSE_REVOCATION).isValid)
    }

    @Test
    fun `resource unused bits2 value is an error`() {
        val result = verifyWith("statuslist_bits2_unused.cwt")
        assertStatusError(result, StatusCheckErrorCode.STATUS_LIST_MALFORMED)
    }

    @Test
    fun `resource bits4 CWT is unsupported`() {
        val result = verifyWith("statuslist_bits4.cwt")
        assertStatusError(result, StatusCheckErrorCode.STATUS_PROFILE_UNSUPPORTED)
    }

    @Test
    fun `resource expired CWT is expired`() {
        val result = verifyWith("statuslist_expired.cwt")
        assertStatusError(result, StatusCheckErrorCode.STATUS_LIST_EXPIRED)
    }

    @Test
    fun `resource bad signature CWT fails signature`() {
        val result = verifyWith("statuslist_badsig.cwt")
        assertStatusError(result, StatusCheckErrorCode.STATUS_LIST_INVALID_SIGNATURE)
    }

    @Test
    fun `resource wrong sub CWT mismatches uri`() {
        val result = verifyWith("statuslist_wrong_sub.cwt")
        assertStatusError(result, StatusCheckErrorCode.STATUS_LIST_URI_MISMATCH)
    }

    private fun verifyWith(cwtName: String): CredentialVerificationSummary {
        mockHttpBytesResponse(STATUS_URI, readBytes("mso_mdoc/status/$cwtName"))
        return verifier.verifyAndGetCredentialStatus(mdocWithStatus, MSO_MDOC)
    }

    private fun assertStatusError(
        result: CredentialVerificationSummary,
        errorCode: StatusCheckErrorCode
    ) {
        listOf(STATUS_PURPOSE_REVOCATION, STATUS_PURPOSE_SUSPENSION).forEach { purpose ->
            val status = result.credentialStatus.getValue(purpose)
            assertFalse(status.isValid)
            assertEquals(errorCode, status.error?.errorCode)
        }
    }

    private fun assertRevocationOnlyPassing(status: Map<String, CredentialStatusResult>) {
        assertEquals(setOf(STATUS_PURPOSE_REVOCATION), status.keys)
        assertTrue(status.getValue(STATUS_PURPOSE_REVOCATION).isValid)
        assertNull(status.getValue(STATUS_PURPOSE_REVOCATION).error)
    }

    private fun assertPassingStatus(status: Map<String, CredentialStatusResult>) {
        assertEquals(setOf(STATUS_PURPOSE_REVOCATION, STATUS_PURPOSE_SUSPENSION), status.keys)
        status.values.forEach {
            assertTrue(it.isValid)
            assertNull(it.error)
        }
    }

    private fun readText(path: String): String =
        String(Files.readAllBytes(ResourceUtils.getFile("classpath:$path").toPath()))

    private fun readBytes(path: String): ByteArray =
        Files.readAllBytes(ResourceUtils.getFile("classpath:$path").toPath())
}
