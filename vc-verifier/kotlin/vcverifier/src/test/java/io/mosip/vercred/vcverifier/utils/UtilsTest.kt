package io.mosip.vercred.vcverifier.utils

import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.data.VerificationResult
import io.mosip.vercred.vcverifier.data.VerificationStatus
import io.mosip.vercred.vcverifier.utils.Util.isValidHttpsUri
import org.json.JSONArray
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.threeten.bp.OffsetDateTime
import org.threeten.bp.ZoneOffset
import org.threeten.bp.format.DateTimeFormatter
import java.io.ByteArrayOutputStream
import java.util.Date


class UtilsTest {

    private val utils = Util
    private val dateUtils = DateUtils

    @Test
    fun `test validate date invalid`() {
        val result = dateUtils.isValidDate("123456789")
        assertFalse(result)
    }

    @Test
    fun `test validate date valid`() {
        val result = dateUtils.isValidDate("2024-09-02T17:36:13.644Z")
        assertTrue(result)
    }

    @Test
    fun `test validate uri invalid`() {
        val result = utils.isValidUri("invalid_uri")
        assertFalse(result)
    }
    @Test
    fun `test validate urn`() {
        val result = utils.isValidUri("urn:eudi:pid:1")
        assertTrue(result)
    }

    @Test
    fun `test validate uri valid`() {
        val result = utils.isValidUri("http://www.google.com")
        assertTrue(result)
    }

    @Test
    fun `test validate uri valid did`() {
        val result = utils.isValidUri("did:jwk:eysdsdsd")
        assertTrue(result)
    }

    @Test
    fun `test empty JSONArray`() {
        val jsonArray = JSONArray()
        val result = utils.jsonArrayToList(jsonArray)
        assertEquals(emptyList<Any>(), result)
    }

    @Test
    fun `test JSONArray with strings`() {
        val jsonArray = JSONArray()
        jsonArray.put("element1")
        jsonArray.put("element2")
        jsonArray.put("element3")

        val result = utils.jsonArrayToList(jsonArray)
        assertEquals(listOf("element1", "element2", "element3"), result)
    }

    @Test
    fun `date expired`() {
        val result = dateUtils.isVCExpired("2024-11-27T13:49:13.644Z")
        assertTrue(result)
    }

    @Test
    fun `date not expired`() {
        val result = dateUtils.isVCExpired("2034-11-02T17:36:13.644Z")
        assertFalse(result)
    }

    @Test
    fun `invalid date`() {
        val result = dateUtils.isFutureDateWithTolerance("12345")
        assertFalse(result)
    }

    @Test
    fun `test calculation of message digest`() {
        val byteArrayOutputStream = ByteArrayOutputStream()
        byteArrayOutputStream.write("hello".toByteArray())


        val digest: ByteArray = Util.calculateDigest("SHA-256", byteArrayOutputStream)

        assertArrayEquals(
            byteArrayOf(
                44,
                -14,
                77,
                -70,
                95,
                -80,
                -93,
                14,
                38,
                -24,
                59,
                42,
                -59,
                -71,
                -30,
                -98,
                27,
                22,
                30,
                92,
                31,
                -89,
                66,
                94,
                115,
                4,
                51,
                98,
                -109,
                -117,
                -104,
                36
            ), (digest)
        )
    }

    @Test
    fun `test when issuanceDate time is not future date and less than currentDate time `() {
        val currentDate = Date()
        val issuanceDate = Date(currentDate.time - 10000).toString()

        val result = dateUtils.isFutureDateWithTolerance(issuanceDate)
        assertFalse(result)
    }

    @Test
    fun `test when issuanceDate time is not future date and 3 seconds less than currentDate time `() {
        val currentDate = Date()
        val issuanceDate = Date(currentDate.time - 3000).toString()

        val result = dateUtils.isFutureDateWithTolerance(issuanceDate)
        assertFalse(result)
    }

    @Test
    fun `test when issuanceDate time equal to future date time`() {
        val currentDate = Date()
        val issuanceDate = Date(currentDate.time).toString()

        val result = dateUtils.isFutureDateWithTolerance(issuanceDate)
        assertFalse(result)
    }


    @Test
    fun `test when issuanceDate time is future date time but within tolerance range`() {
        val currentDate = Date()
        val issuanceDate = Date(currentDate.time + 3000).toString()

        val result = dateUtils.isFutureDateWithTolerance(issuanceDate)
        assertFalse(result)
    }

    @Test
    fun `test when issuanceDate time is future date time but outside tolerance range`() {
        val currentDateTime = OffsetDateTime.now(ZoneOffset.UTC)
        val futureDateTime = currentDateTime.plusSeconds(5)
        val issuanceDate = futureDateTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)

        val result = dateUtils.isFutureDateWithTolerance(issuanceDate)
        assertTrue(result)
    }

    @Test
    fun `test when issuanceDate is empty`() {
        val result = dateUtils.isFutureDateWithTolerance("")
        assertFalse(result)
    }

    @Test
    fun `valid HTTPS URL with host`() {
        assertTrue(isValidHttpsUri("https://example.com"))
    }

    @Test
    fun `valid HTTPS URL with port and path`() {
        assertTrue(isValidHttpsUri("https://example.com:443/path"))
    }

    @Test
    fun `valid HTTPS URL with trailing slash`() {
        assertTrue(isValidHttpsUri("https://example.com/"))
    }

    @Test
    fun `invalid HTTP URL`() {
        assertFalse(isValidHttpsUri("http://example.com"))
    }

    @Test
    fun `missing scheme`() {
        assertFalse(isValidHttpsUri("example.com"))
    }

    @Test
    fun `empty string`() {
        assertFalse(isValidHttpsUri(""))
    }

    @Test
    fun `null host`() {
        assertFalse(isValidHttpsUri("https:///path"))
    }

    @Test
    fun `getVerificationStatus returns SUCCESS when verificationStatus is true and no error code`() {
        val result = VerificationResult(
            verificationStatus = true,
            verificationMessage = "Valid VC",
            verificationErrorCode = ""
        )

        val status = Util.getVerificationStatus(result)
        assertEquals(VerificationStatus.SUCCESS, status)
    }

    @Test
    fun `getVerificationStatus returns EXPIRED when error code is VC_EXPIRED`() {
        val result = VerificationResult(
            verificationStatus = true,
            verificationMessage = "Expired",
            verificationErrorCode = CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED
        )

        val status = Util.getVerificationStatus(result)
        assertEquals(VerificationStatus.EXPIRED, status)
    }

    @Test
    fun `getVerificationStatus returns INVALID when signature is invalid`() {
        val result = VerificationResult(
            verificationStatus = false,
            verificationMessage = "Invalid signature",
            verificationErrorCode = "SIGNATURE_INVALID"
        )

        val status = Util.getVerificationStatus(result)
        assertEquals(VerificationStatus.INVALID, status)
    }
}