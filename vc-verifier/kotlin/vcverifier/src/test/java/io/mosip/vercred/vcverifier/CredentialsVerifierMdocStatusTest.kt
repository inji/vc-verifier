package io.mosip.vercred.vcverifier

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import io.mosip.vercred.vcverifier.constants.CredentialFormat.MSO_MDOC
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALID_UNTIL_MSO
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PURPOSE_REVOCATION
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PURPOSE_SUSPENSION
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_RESULT_KEY
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.data.CredentialVerificationSummary
import io.mosip.vercred.vcverifier.exception.NetworkManagerClientExceptions
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.testHelpers.MdocStatusListFixtures
import io.mosip.vercred.vcverifier.testHelpers.MdocStatusListFixtures.STATUS_URI
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import testutils.mockHttpBytesResponse

class CredentialsVerifierMdocStatusTest {

    private val verifier = CredentialsVerifier()
    private val mdocWithStatus = MdocStatusListFixtures.mdocWithStatus()
    private val mdocNoStatus = MdocStatusListFixtures.mdocNoStatus()

    @BeforeEach
    fun setup() {
        mockkObject(NetworkManagerClient.Companion)
    }

    @AfterEach
    fun teardown() {
        unmockkObject(NetworkManagerClient.Companion)
    }

    @Test
    fun `valid mDoc plus VALID CWT returns crypto OK and valid status`() {
        val result = verifyWith(validCwt())

        assertTrue(result.verificationResult.verificationStatus)
        val status = result.credentialStatus.getValue(STATUS_RESULT_KEY)
        assertTrue(status.isValid)
        assertNull(status.error)
    }

    @Test
    fun `same mDoc plus INVALID CWT returns crypto OK and revocation`() {
        val result = verifyWith(invalidCwt())

        assertTrue(result.verificationResult.verificationStatus)
        val status = result.credentialStatus.getValue(STATUS_PURPOSE_REVOCATION)
        assertFalse(status.isValid)
        assertNull(status.error)
    }

    @Test
    fun `same mDoc plus SUSPENDED CWT bits 2 returns crypto OK and suspension`() {
        val result = verifyWith(suspendedCwt())

        assertTrue(result.verificationResult.verificationStatus)
        val status = result.credentialStatus.getValue(STATUS_PURPOSE_SUSPENSION)
        assertFalse(status.isValid)
        assertNull(status.error)
    }

    @Test
    fun `bits 2 value 0 is VALID`() {
        val result = verifyWith(MdocStatusListFixtures.statusListCwt(bits = 2, valuesAtIndex = intArrayOf(0)))

        assertTrue(result.credentialStatus.getValue(STATUS_RESULT_KEY).isValid)
    }

    @Test
    fun `bits 2 value 1 is INVALID`() {
        val result = verifyWith(MdocStatusListFixtures.statusListCwt(bits = 2, valuesAtIndex = intArrayOf(1)))

        assertFalse(result.credentialStatus.getValue(STATUS_PURPOSE_REVOCATION).isValid)
    }

    @Test
    fun `bits 2 value 3 is an error and not VALID`() {
        val result = verifyWith(MdocStatusListFixtures.statusListCwt(bits = 2, valuesAtIndex = intArrayOf(3)))

        assertTrue(result.verificationResult.verificationStatus)
        assertStatusError(result, StatusCheckErrorCode.STATUS_LIST_MALFORMED)
    }

    @Test
    fun `bits 4 is STATUS_PROFILE_UNSUPPORTED`() {
        val result = verifyWith(MdocStatusListFixtures.statusListCwt(bits = 4, valuesAtIndex = intArrayOf(0)))

        assertStatusError(result, StatusCheckErrorCode.STATUS_PROFILE_UNSUPPORTED)
    }

    @Test
    fun `expired mDoc plus VALID CWT fails crypto and never fetches status list`() {
        mockHttpBytesResponse(STATUS_URI, validCwt())

        val result = verifier.verifyAndGetCredentialStatus(
            MdocStatusListFixtures.mdocExpired(),
            MSO_MDOC
        )

        assertFalse(result.verificationResult.verificationStatus)
        assertEquals(ERROR_CODE_INVALID_VALID_UNTIL_MSO, result.verificationResult.verificationErrorCode)
        assertTrue(result.credentialStatus.isEmpty())
        verify(exactly = 0) { NetworkManagerClient.sendHTTPRequestBytes(any(), any(), any()) }
    }

    @Test
    fun `no status_list skips status check and never fetches status list`() {
        mockHttpBytesResponse(STATUS_URI, validCwt())

        val result = verifier.verifyAndGetCredentialStatus(mdocNoStatus, MSO_MDOC)

        assertTrue(result.verificationResult.verificationStatus)
        assertTrue(result.credentialStatus.isEmpty())
        verify(exactly = 0) { NetworkManagerClient.sendHTTPRequestBytes(any(), any(), any()) }
    }

    @Test
    fun `status list HTTP failure returns STATUS_LIST_FETCH_FAILED`() {
        every { NetworkManagerClient.sendHTTPRequestBytes(STATUS_URI, any(), any()) } throws
            NetworkManagerClientExceptions.NetworkRequestFailed("404")

        val result = verifier.verifyAndGetCredentialStatus(mdocWithStatus, MSO_MDOC)

        assertTrue(result.verificationResult.verificationStatus)
        assertStatusError(result, StatusCheckErrorCode.STATUS_LIST_FETCH_FAILED)
    }

    @Test
    fun `bad signature returns matching error and status is not VALID`() {
        val result = verifyWith(
            MdocStatusListFixtures.statusListCwt(bits = 1, valuesAtIndex = intArrayOf(0), corruptSignature = true)
        )

        assertTrue(result.verificationResult.verificationStatus)
        assertStatusError(result, StatusCheckErrorCode.STATUS_LIST_INVALID_SIGNATURE)
    }

    @Test
    fun `wrong sub returns matching error and status is not VALID`() {
        val result = verifyWith(
            MdocStatusListFixtures.statusListCwt(
                bits = 1,
                valuesAtIndex = intArrayOf(0),
                uri = MdocStatusListFixtures.WRONG_STATUS_URI
            )
        )

        assertStatusError(result, StatusCheckErrorCode.STATUS_LIST_URI_MISMATCH)
    }

    @Test
    fun `expired CWT returns matching error and status is not VALID`() {
        val result = verifyWith(
            MdocStatusListFixtures.statusListCwt(
                bits = 1,
                valuesAtIndex = intArrayOf(0),
                exp = MdocStatusListFixtures.EXPIRED_EXP
            )
        )

        assertStatusError(result, StatusCheckErrorCode.STATUS_LIST_EXPIRED)
    }

    @Test
    fun `idx out of range returns matching error and status is not VALID`() {
        val result = verifyWith(MdocStatusListFixtures.emptyListCwt())

        assertStatusError(result, StatusCheckErrorCode.STATUS_LIST_INDEX_OUT_OF_BOUNDS)
    }

    @Test
    fun `missing x5chain returns STATUS_LIST_UNTRUSTED_ISSUER`() {
        val result = verifyWith(
            MdocStatusListFixtures.statusListCwt(
                bits = 1,
                valuesAtIndex = intArrayOf(0),
                includeX5chain = false
            )
        )

        assertStatusError(result, StatusCheckErrorCode.STATUS_LIST_UNTRUSTED_ISSUER)
    }

    @Test
    fun `mso_mdoc checkStatus reads status list instead of throwing`() {
        mockHttpBytesResponse(STATUS_URI, validCwt())

        val status = MsoMdocVerifiableCredential().checkStatus(mdocWithStatus, null)

        assertTrue(status.getValue(STATUS_RESULT_KEY).isValid)
    }

    @Test
    fun `existing verify credential format path is unchanged for generated mDoc`() {
        val verificationResult = verifier.verify(mdocWithStatus, MSO_MDOC)

        assertTrue(verificationResult.verificationStatus)
        assertEquals("", verificationResult.verificationErrorCode)
    }

    private fun verifyWith(cwt: ByteArray): CredentialVerificationSummary {
        mockHttpBytesResponse(STATUS_URI, cwt)
        return verifier.verifyAndGetCredentialStatus(mdocWithStatus, MSO_MDOC)
    }

    private fun assertStatusError(
        result: CredentialVerificationSummary,
        errorCode: StatusCheckErrorCode
    ) {
        val status: CredentialStatusResult = result.credentialStatus.getValue(STATUS_RESULT_KEY)
        assertFalse(status.isValid)
        assertEquals(errorCode, status.error?.errorCode)
    }

    private fun validCwt() = MdocStatusListFixtures.statusListCwt(bits = 1, valuesAtIndex = intArrayOf(0))
    private fun invalidCwt() = MdocStatusListFixtures.statusListCwt(bits = 1, valuesAtIndex = intArrayOf(1))
    private fun suspendedCwt() = MdocStatusListFixtures.statusListCwt(bits = 2, valuesAtIndex = intArrayOf(2))
}
