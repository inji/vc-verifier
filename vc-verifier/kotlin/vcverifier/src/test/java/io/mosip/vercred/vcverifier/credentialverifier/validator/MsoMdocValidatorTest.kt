package io.mosip.vercred.vcverifier.credentialverifier.validator

import android.os.Build
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALID_FROM_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALID_UNTIL_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MDL_ELEMENT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALIDITY_INFO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALIDITY_INFO_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALID_FROM_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALID_UNTIL_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_EXPECTED_UPDATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_SIGNED_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DIGEST_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MSO_DATE_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MSO_VERSION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DIGEST_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MSO_DATE_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MSO_VERSION
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.BuildConfig
import io.mosip.vercred.vcverifier.utils.DateUtils
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import testutils.readClasspathFile
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALUE_DIGESTS_STRUCTURE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MSO_DIGEST_ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_VALID_FROM_BEFORE_SIGNED_MSO
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MDOC_CLOCK_SKEW_TOLERANCE_MS
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerificationOptions
import java.io.ByteArrayOutputStream
import java.time.Instant
import java.util.Base64
import java.util.Date

private const val MSO_DATE_TAG = 0L
private const val MSO_TAG24 = 24L

/** A docType with no docType-specific checks, so these tests exercise only the generic MSO checks. */
private const val GENERIC_DOC_TYPE = "org.example.generic.1"
private const val MDL_DOC_TYPE = "org.iso.18013.5.1.mDL"

/**
 * Builds a tagged (tag 0 / "tdate") CBOR UnicodeString for use as validFrom / validUntil / signed / expectedUpdate.
 */
private fun taggedDate(value: String): DataItem {
    val item = UnicodeString(value)
    item.setTag(MSO_DATE_TAG)
    return item
}

/**
 * Builds a minimal, structurally valid MSO map that satisfies MsoMdocValidator's mandatory field
 * checks, with a customizable validityInfo section for exercising validity-info specific failures.
 */
private fun buildMso(
    includeValidFrom: Boolean = true,
    includeValidUntil: Boolean = true,
    includeSigned: Boolean = true,
    validFrom: DataItem = taggedDate("2024-10-23T07:01:17Z"),
    validUntil: DataItem = taggedDate("2026-10-23T07:01:17Z"),
    signed: DataItem = taggedDate("2024-10-23T07:01:17Z"),
    expectedUpdate: DataItem? = null,
    docType: String = GENERIC_DOC_TYPE,
): Map {
    val validityInfo = Map()
    if (includeValidFrom) validityInfo.put(UnicodeString("validFrom"), validFrom)
    if (includeValidUntil) validityInfo.put(UnicodeString("validUntil"), validUntil)
    if (includeSigned) validityInfo.put(UnicodeString("signed"), signed)
    if (expectedUpdate != null) validityInfo.put(UnicodeString("expectedUpdate"), expectedUpdate)

    return Map().apply {
        put(UnicodeString("version"), UnicodeString("1.0"))
        put(UnicodeString("digestAlgorithm"), UnicodeString("SHA-256"))
        put(UnicodeString("valueDigests"), Map())
        put(UnicodeString("deviceKeyInfo"), Map())
        put(UnicodeString("docType"), UnicodeString(docType))
        put(UnicodeString("validityInfo"), validityInfo)
    }
}

private fun encode(dataItem: DataItem): ByteArray =
    ByteArrayOutputStream().also { CborEncoder(it).encode(dataItem) }.toByteArray()

/**
 * Builds a base64url-encoded (OpenID4VCI 1.0 / "latest") mDoc credential string wrapping the given MSO,
 * suitable for exercising [MsoMdocValidator.validate] without requiring a real signature.
 */
private fun buildMdocCredential(mso: Map): String {
    val taggedMsoBytes = ByteString(encode(mso)).apply { setTag(MSO_TAG24) }
    val payload = ByteString(encode(taggedMsoBytes))

    val issuerAuth = Array().apply {
        add(ByteString(ByteArray(0)))
        add(Map())
        add(payload)
        add(ByteString(ByteArray(4)))
    }

    val credential = Map().apply {
        put(UnicodeString("issuerAuth"), issuerAuth)
        put(UnicodeString("nameSpaces"), Map())
    }

    return Base64.getUrlEncoder().withoutPadding().encodeToString(encode(credential))
}

/** Pinned clocks relative to the default 2024-10-23 .. 2026-10-23 validity window. */
private const val BEFORE_WINDOW = "2024-01-01T00:00:00Z"
private const val IN_WINDOW = "2025-06-01T00:00:00Z"
private const val AFTER_WINDOW = "2027-01-01T00:00:00Z"

/** Inside the static mdl-* samples' window (validFrom 2026-11-15, validUntil 2031-11-16); mdl-expired ended 2026-11-15. */
private const val STATIC_SAMPLE_NOW = "2027-06-01T00:00:00Z"

private fun validatorAt(now: String) = validatorAt(Instant.parse(now).toEpochMilli())

private fun validatorAt(nowMillis: Long) =
    MsoMdocValidator(MsoMdocVerificationOptions(currentTimeMillis = { nowMillis }))

private fun millis(date: String): Long = Instant.parse(date).toEpochMilli()

/** Builds a legacy (shape B: docType + issuerSigned) credential wrapping the given MSO. */
private fun buildLegacyMdocCredential(mso: Map): String {
    val issuerAuth = Array().apply {
        add(ByteString(ByteArray(0)))
        add(Map())
        add(ByteString(encode(ByteString(encode(mso)).apply { setTag(MSO_TAG24) })))
        add(ByteString(ByteArray(4)))
    }
    val credential = Map().apply {
        put(UnicodeString("docType"), UnicodeString(GENERIC_DOC_TYPE))
        put(
            UnicodeString("issuerSigned"),
            Map().apply {
                put(UnicodeString("issuerAuth"), issuerAuth)
                put(UnicodeString("nameSpaces"), Map())
            }
        )
    }
    return Base64.getUrlEncoder().withoutPadding().encodeToString(encode(credential))
}

/** Builds a shape C (documents[]) credential wrapping the given MSO. */
private fun buildDocumentsMdocCredential(mso: Map): String {
    val issuerAuth = Array().apply {
        add(ByteString(ByteArray(0)))
        add(Map())
        add(ByteString(encode(ByteString(encode(mso)).apply { setTag(MSO_TAG24) })))
        add(ByteString(ByteArray(4)))
    }
    val document = Map().apply {
        put(UnicodeString("docType"), UnicodeString(GENERIC_DOC_TYPE))
        put(
            UnicodeString("issuerSigned"),
            Map().apply {
                put(UnicodeString("issuerAuth"), issuerAuth)
                put(UnicodeString("nameSpaces"), Map())
            }
        )
    }
    val credential = Map().apply { put(UnicodeString("documents"), Array().apply { add(document) }) }
    return Base64.getUrlEncoder().withoutPadding().encodeToString(encode(credential))
}

/** Shape A = latest IssuerSigned, B = docType + issuerSigned, C = documents[]. */
private fun buildCredential(shape: String, mso: Map): String = when (shape) {
    "A" -> buildMdocCredential(mso)
    "B" -> buildLegacyMdocCredential(mso)
    else -> buildDocumentsMdocCredential(mso)
}

class MsoMdocValidatorTest {
    @BeforeEach
    fun setUp() {
        mockkObject(BuildConfig)
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O

        mockkObject(DateUtils)
        every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)
        every { DateUtils.parseDate("2026-10-23T07:01:17Z") } returns Date(1792738877000L)
        every { DateUtils.isIsoMsoDateTime(any()) } answers { callOriginal() }
        every { DateUtils.isIsoFullDate(any()) } answers { callOriginal() }

    }

    @AfterEach
    fun after() {
        clearAllMocks()
    }

//    / Legacy

    @Test
    fun `should return true when credential is successfully validated`() {

        val isVerified = validatorAt(STATIC_SAMPLE_NOW).validate(readClasspathFile("mso_mdoc/mdl-valid.b64url").trim())

        assertTrue(isVerified)
    }

    @Test
    fun `should throw when validFrom is a future date for legacy structure`() {

        val verificationException = assertThrows(ValidationException::class.java) {
            validatorAt(BEFORE_WINDOW).validate(
                buildLegacyMdocCredential(buildMso())
            )
        }

        assertEquals(ERROR_CURRENT_DATE_BEFORE_VALID_FROM, verificationException.errorMessage)
        assertEquals(ERROR_CODE_CURRENT_DATE_BEFORE_VALID_FROM, verificationException.errorCode)
    }

    @Test
    fun `should throw ERR_VC_EXPIRED when validUntil is in the past`() {

        val verificationException = assertThrows(ValidationException::class.java) {
            validatorAt(STATIC_SAMPLE_NOW).validate(readClasspathFile("mso_mdoc/mdl-expired.b64url").trim())
        }

        assertEquals(ERROR_MESSAGE_VC_EXPIRED, verificationException.errorMessage)
        assertEquals(ERROR_CODE_VC_EXPIRED, verificationException.errorCode)
    }

    @Test
    fun `should run the mDL field checks only for the mDL docType`() {
        // The same MSO with no disclosed elements: an mDL needs its mandatory elements, other docTypes do not.
        assertTrue(validatorAt(IN_WINDOW).validate(buildMdocCredential(buildMso())))
        val exception = assertThrows(ValidationException::class.java) {
            validatorAt(IN_WINDOW).validate(buildMdocCredential(buildMso(docType = MDL_DOC_TYPE)))
        }
        assertEquals(ERROR_CODE_INVALID_MDL_ELEMENT, exception.errorCode)
    }

    @Test
    fun `should run the mDL field checks before reporting expiry`() {
        val exception = assertThrows(ValidationException::class.java) {
            validatorAt(AFTER_WINDOW).validate(buildMdocCredential(buildMso(docType = MDL_DOC_TYPE)))
        }
        assertEquals(ERROR_CODE_INVALID_MDL_ELEMENT, exception.errorCode)
    }

    @Test
    fun `should throw exception string when issuerAuth is not available`() {
        assertThrows(UnknownException::class.java) {
            MsoMdocValidator().validate(
                "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSham5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xiNgYWFWkaGRpZ2VzdElEAmZyYW5kb21QbYUstb5qYaqaDGEXvWdD53FlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVmQWdhdGhh2BhYVKRoZGlnZXN0SUQGZnJhbmRvbVDcl4VzmY5oXohcs2H4bJdGcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlZkpvc2VwaNgYWIGkaGRpZ2VzdElEA2ZyYW5kb21QIL6_sBEAsnZUVxjDD0BsyHFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRlbGVsZW1lbnRWYWx1ZVgyrO0ABXNyAA1qYXZhLnRpbWUuU2VylV2EuhsiSLIMAAB4cHcNAgAAAAA5hMGAAAAAAHjYGFhqpGhkaWdlc3RJRAFmcmFuZG9tUOOhiP_xEFnrb7zmJlXfvW9xZWxlbWVudElkZW50aWZpZXJqaXNzdWVfZGF0ZWxlbGVtZW50VmFsdWV4GzIwMjQtMTAtMDhUMDI6MDc6NTkuMjI2OTYwWtgYWGukaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZWxlbGVtZW50VmFsdWV4GzIwMjQtMTAtMjBUMDI6MDc6NTkuMjI2OTYwWtgYWFmkaGRpZ2VzdElEAGZyYW5kb21QBYNczBataC2MR4om9FAnmHFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlZklzbGFuZNgYWFSkaGRpZ2VzdElEB2ZyYW5kb21QSVmbVt1TszUaVytA8n9y03FlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXJsZWxlbWVudFZhbHVlGHvYGFkBUaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVycmRyaXZpbmdfcHJpdmlsZWdlc2xlbGVtZW50VmFsdWVY-qztAAVzcgAXamF2YS51dGlsLkxpbmtlZEhhc2hNYXA0wE5cEGzA-wIAAVoAC2FjY2Vzc09yZGVyeHIAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA_QAAAAAAABncIAAAACAAAAAN0ABV2ZWhpY2xlX2NhdGVnb3J5X2NvZGV0AAFBdAAKaXNzdWVfZGF0ZXQAGzIwMjQtMTAtMDhUMDI6MDc6NTkuMjI2OTYwWnQAC2V4cGlyeV9kYXRldAAbMjAyNC0xMC0yMFQwMjowNzo1OS4yMjY5NjBaeAA"
            )
        }
    }

    @Test
    fun `should throw exception when credential is not properly base64 url encoded`() {
        val exception = assertThrows(UnknownException::class.java) {
            MsoMdocValidator().validate(
                "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkBxDCCAcAwggFloAMCAQICFH6lICTsAhkMivItOT9v6JeZubwmMAoGCCqGSM49BAMCME4xCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTERMA8GA1UEBwwITW9ja0NpdHkxDTALBgNVBAoMBE1vY2sxDTALBgNVBAsMBE1vY2swHhcNMjQxMDIyMDcwMjUwWhcNMjUxMDIyMDcwMjUwWjBOMQswCQYDVQQGEwJNSzEOMAwGA1UECAwFTUstS0ExETAPBgNVBAcMCE1vY2tDaXR5MQ0wCwYDVQQKDARNb2NrMQ0wCwYDVQQLDARNb2NrMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjtRcOXgIyR_xqGB-M6d0qkrjQWOBGGdlPgfIfb2xW0egZAVEz_55IXCofWaprRGxX7qQTlNAZyByniay2jzhR6MhMB8wHQYDVR0OBBYEFNqAHypQYcwWoeUfmMv4SbztomFvMAoGCCqGSM49BAMCA0kAMEYCIQDsgsz9wCa56ukpfyvq9371b5GhkSZb38G7xFofWgFtJwIhAKxACllIOtcleKETDFGa3araADjKd2isahQtXZwQmPr1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggd4bqGFzNwBXyzdGmeipRMfjTQKQuzs6nvM7Z1AXsFBQGWCCaGHxiAeoHvfCNpkG3XpGTTQ787Fg9f3R9UTvKGa0mqwNYICnPRqwtKq9fYqI0sR96Ha3151joEQb24VAzTK4jw8puAVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjNUMDc6MDE6MTdaaXZhbGlkRnJvbcB0MjAyNC0xMC0yM1QwNzowMToxN1pqdmFsaWRVbnRpbMB0MjAyNi0xMC0yM1QwNzowMToxN1pYQOkgtaSchZRTPO01AjYgnKBT9mgXG4NUWsp_W5pCxz5eyB6SIpL9lVYg3tPOkTfYggsVSgPO8ostvTXn7DsBRl5qbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYWKRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVlajIwMjQtMTAtMjPYGFhZpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVlajIwMjktMTAtMjPYGFifpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyNC0xMC0yMywgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwMjktMTAtMjN92BhYRoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVkMTIzM9gYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYk1L2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE="
            )
        }

        assertEquals(
            "Error while doing validation of credential - Error on decoding base64Url encoded data Last unit does not have enough valid bits",
            exception.message
        )
    }

    // Latest

    @Test
    fun `should throw when the mso-validityInfo-signed or validFrom or validUntil is not tdate format`() {
        val mdocsWithInvalidValidityInfo = listOf(
            // _validFrom - not in tdate format
            Pair("omppc3N1ZXJBdXRohEOhASahGCFZAxQwggMQMIIB-KADAgECAggGru5Xjrda-DANBgkqhkiG9w0BAQsFADB4MQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9SRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMR8wHQYDVQQDDBZ3d3cuZXhhbXBsZS5jb20gKFJPT1QpMB4XDTI2MDcxMzA2MzY0NloXDTI5MDcxMjA2MzY0NlowgZsxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxQjBABgNVBAMMOXd3dy5leGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VDX1IxLUVDX1NFQ1AyNTZSMV9TSUdOKTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCxNsdJnJDCpzS-oiskMiAXKts0KfSq0bKAcAF9AIVcylo234k6c5ze6zd-LYUq4qZt2Epj0JtzVJzWtXJBmy5-jRTBDMBIGA1UdEwEB_wQIMAYBAf8CAQEwHQYDVR0OBBYEFNTUxJGN9cvnw0bkpOY7hXCOgEIgMA4GA1UdDwEB_wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEAdCMKCVQqQFNuXfZVD2JrmGHMdqmBsyEITavF8uIjOUu39qaaXyhvLeCggP7PjXJ8Cu141VKCkj6XHtvHM5iqCQsAQpjgzp6Hi27sau_yKLOOKBz8E2G9N9-skn9UiVJqSeZLOl_gRcPhbxVndQp7FZ4cdct4r_kObVt-W-BTlDJWjz54bPVhInnFfLpv2KlSqASRBIpbasMehVaYR7E9Rq_Ya5Ms5A8MYzXzdLeBdSWJCIyxmHasTax6cVM5GdqpAOjbJF_7k7X4JHBEIiDrJ_O0p9zwpBWdAn_Kb-oCe3VQHzrmeCsp2uyNRvzEqJ5Yd5b26-V8C8yBj7P7Uaa-PlkCSdgYWQJEpmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB4GDIwMjYtMDctMjdUMDc6MDA6MTQuNTQyWml2YWxpZEZyb214GDIwMjYtMDctMjdUMDc6MDA6MTQuNTQyWmp2YWxpZFVudGlswHgYMjAyOC0wNy0yN1QwNzowMDoxNC41NDJabHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGmAFggTr5oMGcGw43-T1J_2msjv9BzxaJus3ThpHGM3zHFm7kBWCA2lj7f62WqfeYVJi2m0d6AY8k9hRyq4RcKSuxA-oP20gJYIILEKoo6H7qmFdfyyJ0cpCoE3rrPuAYHegLBSYWuaxG0A1ggbMB0TTdQguMgGxw-p2mMIcM_6Jm-aqz-yPJZ20EJngsEWCBCIZA-PL8wVIB351NBBPG3_XNHFjFT3kxHkkV3xfABUAVYIL8fSvu6V86UEugh6yi8sSVcbMrInbigtIn6SFoBn1oAbWRldmljZUtleUluZm-haWRldmljZUtleaYBAgJYK1F3cXBQOUdySTc1Wjk5dGFvMTZ1V3BiMWM5Q1gzdkJUaGstcGVIZFR0RHMDJiABIVgg8sPSM4-Iv-igNTVptIBcMTUhr4kf-QM6YPRS8bgdaTMiWCDB__3qgSDY3rxDwN7eymTsFYI5TLa22CaQP2ge8JmcCm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhA6ee35rNG1fXua9zSbswVgw-Oj-Bhl06T3_CFrQT2TBw-53UYzvklcPTDgOF2aGnIQ12C_A15xm4Ttrew_4s0e2puYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYbYGFhlpGZyYW5kb21YGI8C8DQJK_SUZBXsmRCbJLXiUn1K3YYR4WhkaWdlc3RJRABsZWxlbWVudFZhbHVlbSR7ZmFtaWx5TmFtZX1xZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhjpGZyYW5kb21YGLw2rltRx5KSMYIk-_JoNPUFIf2xqvKhBGhkaWdlc3RJRAFsZWxlbWVudFZhbHVlbCR7Z2l2ZW5OYW1lfXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYY6RmcmFuZG9tWBhZRbwFCbo4hGrHimHL0BqPgkAwv4kHWTloZGlnZXN0SUQCbGVsZW1lbnRWYWx1ZWwke2JpcnRoRGF0ZX1xZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWF6kZnJhbmRvbVgYECmebmmoxcajtLD6TyW9BUjGvy3RWcU0aGRpZ2VzdElEA2xlbGVtZW50VmFsdWViSU5xZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ52BhYbaRmcmFuZG9tWBiQyBprNdm2s9RF0FBxWMSMhiMMnDlmFstoZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZXEke2RvY3VtZW50TnVtYmVyfXFlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXLYGFhgpGZyYW5kb21YGEpUte2YuW4fekgKtuhmYYAIln7v-YYBoWhkaWdlc3RJRAVsZWxlbWVudFZhbHVlayR7cG9ydHJhaXR9cWVsZW1lbnRJZGVudGlmaWVyaHBvcnRyYWl0", "validFrom"),
            // signed - not in tdate format
            Pair("omppc3N1ZXJBdXRohEOhASahGCFZAxQwggMQMIIB-KADAgECAggGru5Xjrda-DANBgkqhkiG9w0BAQsFADB4MQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9SRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMR8wHQYDVQQDDBZ3d3cuZXhhbXBsZS5jb20gKFJPT1QpMB4XDTI2MDcxMzA2MzY0NloXDTI5MDcxMjA2MzY0NlowgZsxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxQjBABgNVBAMMOXd3dy5leGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VDX1IxLUVDX1NFQ1AyNTZSMV9TSUdOKTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCxNsdJnJDCpzS-oiskMiAXKts0KfSq0bKAcAF9AIVcylo234k6c5ze6zd-LYUq4qZt2Epj0JtzVJzWtXJBmy5-jRTBDMBIGA1UdEwEB_wQIMAYBAf8CAQEwHQYDVR0OBBYEFNTUxJGN9cvnw0bkpOY7hXCOgEIgMA4GA1UdDwEB_wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEAdCMKCVQqQFNuXfZVD2JrmGHMdqmBsyEITavF8uIjOUu39qaaXyhvLeCggP7PjXJ8Cu141VKCkj6XHtvHM5iqCQsAQpjgzp6Hi27sau_yKLOOKBz8E2G9N9-skn9UiVJqSeZLOl_gRcPhbxVndQp7FZ4cdct4r_kObVt-W-BTlDJWjz54bPVhInnFfLpv2KlSqASRBIpbasMehVaYR7E9Rq_Ya5Ms5A8MYzXzdLeBdSWJCIyxmHasTax6cVM5GdqpAOjbJF_7k7X4JHBEIiDrJ_O0p9zwpBWdAn_Kb-oCe3VQHzrmeCsp2uyNRvzEqJ5Yd5b26-V8C8yBj7P7Uaa-PlkCSdgYWQJEpmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZHgYMjAyNi0wNy0yN1QxMToxODowNC4xODlaaXZhbGlkRnJvbcB4GDIwMjYtMDctMjdUMTE6MTg6MDQuMTg5Wmp2YWxpZFVudGlswHgYMjAyOC0wNy0yN1QxMToxODowNC4xODlabHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGmAFggm_iSMLVKyoA1L0o9dAVItH7a-gB4XpvRRkgs9xUA-g4BWCD_retaORzBbWHpiAlsYQ8ES02IxG3fJ_9UW7ZWUvLMnAJYIJ1nfRdMrl7dgXEYAYUtijatd3-ayXfZttbDn8EU9PnqA1ggF4vDIxFzV0sdnsNO1fku9Mj87HSYtBPzCwIZZoUhBHEEWCDkX5wQ-KjmpHvPVt_R5ToKBmiUAMOAdStedIGzxERtUAVYIJIr-cnFSd83OZwPVQqQbwCl3Y_svcXM3DV_8onS-sbybWRldmljZUtleUluZm-haWRldmljZUtleaYBAgJYK0NmLUV6ZXV4ZVMzc3NmcUpHYUIzTnowNWVVTTAxTG5ndk5FTW9PaUhFa28DJiABIVggEseeNxqppc2Eu9H86Q2WdRlLi7XH3GZ0Si1w4MTTvfAiWCANsbMTjZZ2p7htLmE7V_9-NeuQO97ElcvXIhQqTOOHTG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhA2XpsLCoI65DPopj0keS8XwLFLpFt6Bhg7dEq9IwBVQ55xStt_3zqbmMfjeXOapQf5IlnK2b3wHzGmCW-483almpuYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYbYGFhlpGZyYW5kb21YGBjx8h0xvahI_STeLVCjUDL9mQsPOLzmEGhkaWdlc3RJRABsZWxlbWVudFZhbHVlbSR7ZmFtaWx5TmFtZX1xZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhjpGZyYW5kb21YGFJhw7SSGpp1r1a3_bQ9ZvYj-gApH2Hb72hkaWdlc3RJRAFsZWxlbWVudFZhbHVlbCR7Z2l2ZW5OYW1lfXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYY6RmcmFuZG9tWBgok--ExxhX-in-e7pTEVQXHDar1m_nJQloZGlnZXN0SUQCbGVsZW1lbnRWYWx1ZWwke2JpcnRoRGF0ZX1xZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWF6kZnJhbmRvbVgYncahLAxjCD7cH4vZj9-A0S9TjKE0C1qjaGRpZ2VzdElEA2xlbGVtZW50VmFsdWViSU5xZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ52BhYbaRmcmFuZG9tWBjCvVmMUzVITLOWSQ0-LQ-27WU6Nizy9FdoZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZXEke2RvY3VtZW50TnVtYmVyfXFlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXLYGFhgpGZyYW5kb21YGI6wAqgaoBwR_FnBHevssQ6MUzxXqRQ74mhkaWdlc3RJRAVsZWxlbWVudFZhbHVlayR7cG9ydHJhaXR9cWVsZW1lbnRJZGVudGlmaWVyaHBvcnRyYWl0", "signed"),
            // validUntil - not in tdate format
            Pair("omppc3N1ZXJBdXRohEOhASahGCFZAxQwggMQMIIB-KADAgECAggGru5Xjrda-DANBgkqhkiG9w0BAQsFADB4MQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9SRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMR8wHQYDVQQDDBZ3d3cuZXhhbXBsZS5jb20gKFJPT1QpMB4XDTI2MDcxMzA2MzY0NloXDTI5MDcxMjA2MzY0NlowgZsxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxQjBABgNVBAMMOXd3dy5leGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VDX1IxLUVDX1NFQ1AyNTZSMV9TSUdOKTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCxNsdJnJDCpzS-oiskMiAXKts0KfSq0bKAcAF9AIVcylo234k6c5ze6zd-LYUq4qZt2Epj0JtzVJzWtXJBmy5-jRTBDMBIGA1UdEwEB_wQIMAYBAf8CAQEwHQYDVR0OBBYEFNTUxJGN9cvnw0bkpOY7hXCOgEIgMA4GA1UdDwEB_wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEAdCMKCVQqQFNuXfZVD2JrmGHMdqmBsyEITavF8uIjOUu39qaaXyhvLeCggP7PjXJ8Cu141VKCkj6XHtvHM5iqCQsAQpjgzp6Hi27sau_yKLOOKBz8E2G9N9-skn9UiVJqSeZLOl_gRcPhbxVndQp7FZ4cdct4r_kObVt-W-BTlDJWjz54bPVhInnFfLpv2KlSqASRBIpbasMehVaYR7E9Rq_Ya5Ms5A8MYzXzdLeBdSWJCIyxmHasTax6cVM5GdqpAOjbJF_7k7X4JHBEIiDrJ_O0p9zwpBWdAn_Kb-oCe3VQHzrmeCsp2uyNRvzEqJ5Yd5b26-V8C8yBj7P7Uaa-PlkCSdgYWQJEpmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB4GDIwMjYtMDctMjdUMTE6MjA6NDIuOTk0Wml2YWxpZEZyb23AeBgyMDI2LTA3LTI3VDExOjIwOjQyLjk5NFpqdmFsaWRVbnRpbHgYMjAyOC0wNy0yN1QxMToyMDo0Mi45OTRabHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGmAFggvWwk_lN11yKL-b7I1Z1v-Q5pncY0XOLORldIyERo7QABWCDyJBCqvrqjuklJzTTITFMUFCt6fbscwBWHjGZlPAgxWwJYIEEGdgvqThVsLgMlGwH-TmZJVsKEyx61Zw-jIhgXO4L8A1gg1o1Zn0Y_kGwdc7qq3ds-ucLhrAWL5nVDMQHt7TRs0GgEWCAykurBwuzEshbpyLuTPUPvXSKhL8_uhekrYx2c8LyHOwVYIBDshqdW5zEKEwlnI3H7-59f5cVzfAShRdCmcuqOxGu0bWRldmljZUtleUluZm-haWRldmljZUtleaYBAgJYK2N5d2ZpOWVvekREYzBERnZYRFhRTFpsUVV3cFBOSktfZWZ6c1NibkVZZTQDJiABIVggefasnIhReHeLoXaY8pJBLLpZZKt-By_TsphEMgovoO0iWCB-e7KOjR3LcLnLlbq1SJRmcbyjKULGE5TDaeAAWbBJqW9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAKkhE27B_ghWS2xkzd9rCtsKK1qWrIkmWd6sxYsCYDfKbI9IFkExA6PWEM97MbDwStBKrkGCu8mzXbwdcWqDr6GpuYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYbYGFhlpGZyYW5kb21YGCw-j8fDYKWB-pRPXRcYpL84S8tScCcLNGhkaWdlc3RJRABsZWxlbWVudFZhbHVlbSR7ZmFtaWx5TmFtZX1xZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhjpGZyYW5kb21YGA3h28iTs0FyntLpZq-jpToH9FG3lelnKWhkaWdlc3RJRAFsZWxlbWVudFZhbHVlbCR7Z2l2ZW5OYW1lfXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYY6RmcmFuZG9tWBh9jd0Bp_eH3IwJL0mfaGAsZzioIpfWlO5oZGlnZXN0SUQCbGVsZW1lbnRWYWx1ZWwke2JpcnRoRGF0ZX1xZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWF6kZnJhbmRvbVgYKtO77AJ6q7BxeJHW8ngQUc9mI6OBjybNaGRpZ2VzdElEA2xlbGVtZW50VmFsdWViSU5xZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ52BhYbaRmcmFuZG9tWBhw_qjhwJ3gMYAPaGcAejJ4AGGY-CUggGNoZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZXEke2RvY3VtZW50TnVtYmVyfXFlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXLYGFhgpGZyYW5kb21YGMq7SOOTxBz3TjOelvmod4R5NTk4-kP_4mhkaWdlc3RJRAVsZWxlbWVudFZhbHVlayR7cG9ydHJhaXR9cWVsZW1lbnRJZGVudGlmaWVyaHBvcnRyYWl0", "validUntil")
        )
        val validator = MsoMdocValidator()

        mdocsWithInvalidValidityInfo.forEach { (mdoc, fieldName) ->
            val verificationException = assertThrows(ValidationException::class.java) {
                validator.validate(mdoc)
            }

            assertEquals(
                "Invalid validityInfo - $fieldName is not in date format",
                verificationException.message
            )
            assertEquals("ERR_INVALID_VALIDITY_INFO", verificationException.errorCode)
        }
    }

    @Nested
    @DisplayName("Table-Driven Tests for Date Validation")
    inner class TableDrivenDateValidation {
        
        @ParameterizedTest(name = "now={0} should throw={1}")
        @CsvSource(
            "2024-01-01T00:00:00Z, true",   // before validFrom = throw
            "2027-01-01T00:00:00Z, true",   // after validUntil = throw
            "2025-06-01T00:00:00Z, false"   // inside the validity window
        )
        @DisplayName("Date Range Validation")
        fun testDateRangeValidation(now: String, shouldThrow: Boolean) {
            every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)
            every { DateUtils.parseDate("2026-10-23T07:01:17Z") } returns Date(1792738877000L)

            if (shouldThrow) {
                assertThrows(ValidationException::class.java) {
                    validatorAt(now).validate(
                        buildLegacyMdocCredential(buildMso())
                    )
                }
            } else {
                val isVerified = validatorAt(now).validate(
                    buildLegacyMdocCredential(buildMso())
                )
                assertTrue(isVerified)
            }
        }
    }

    @Nested
    @DisplayName("ValidityInfo Structural Validation Tests")
    inner class ValidityInfoStructuralValidation {

        @Test
        fun `should throw exception when mandatory validityInfo values are not present`() {
            val mso = buildMso(includeValidFrom = false, includeValidUntil = false, includeSigned = false)
            val credential = buildMdocCredential(mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                MsoMdocValidator().validate(credential)
            }

            assertEquals(
                "Invalid validityInfo - mandatory validityInfo values are not present",
                verificationException.errorMessage
            )
            assertEquals(ERROR_CODE_INVALID_DATE_MSO, verificationException.errorCode)
        }

        @Test
        fun `should throw exception when validityInfo-expectedUpdate is invalid in the MSO of the credential`() {
            every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)
            every { DateUtils.parseDate("2026-10-23T07:01:17Z") } returns Date(1792738877000L)

            // expectedUpdate is not tagged as tdate (tag 0), making it structurally invalid
            val invalidExpectedUpdate = UnicodeString("2025-10-23T07:01:17Z")
            val mso = buildMso(expectedUpdate = invalidExpectedUpdate)
            val credential = buildMdocCredential(mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                validatorAt(IN_WINDOW).validate(credential)
            }

            assertEquals("Invalid validityInfo - expectedUpdate is not in date format", verificationException.errorMessage)
            assertEquals(ERROR_CODE_INVALID_VALIDITY_INFO, verificationException.errorCode)
        }

        @Test
        fun `should throw exception when validFrom is invalid in the MSO of the credential`() {
            every { DateUtils.parseDate("invalid-valid-from") } returns null
            every { DateUtils.parseDate("2026-10-23T07:01:17Z") } returns Date(1792738877000L)
            every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)

            val mso = buildMso(validFrom = taggedDate("invalid-valid-from"))
            val credential = buildMdocCredential(mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                MsoMdocValidator().validate(credential)
            }

            assertEquals(ERROR_MESSAGE_INVALID_VALID_FROM_MSO, verificationException.errorMessage)
            assertEquals(ERROR_CODE_INVALID_VALID_FROM_MSO, verificationException.errorCode)
        }

        @Test
        fun `should throw exception when validUntil is invalid in the MSO of the credential`() {
            every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)
            every { DateUtils.parseDate("invalid-valid-until") } returns null

            val mso = buildMso(validUntil = taggedDate("invalid-valid-until"))
            val credential = buildMdocCredential(mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                MsoMdocValidator().validate(credential)
            }

            assertEquals(ERROR_MESSAGE_INVALID_VALID_UNTIL_MSO, verificationException.errorMessage)
            assertEquals(ERROR_CODE_INVALID_VALID_UNTIL_MSO, verificationException.errorCode)
        }

        @Test
        fun `should throw exception when validityInfo-signed is invalid in the MSO of the credential`() {
            every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)
            every { DateUtils.parseDate("2026-10-23T07:01:17Z") } returns Date(1792738877000L)
            every { DateUtils.parseDate("invalid-signed") } returns null

            val mso = buildMso(signed = taggedDate("invalid-signed"))
            val credential = buildMdocCredential(mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                MsoMdocValidator().validate(credential)
            }

            assertEquals(ERROR_MESSAGE_INVALID_SIGNED_MSO, verificationException.errorMessage)
            assertEquals(ERROR_CODE_INVALID_VALIDITY_INFO_MSO, verificationException.errorCode)
        }

        @Test
        fun `should throw exception when validUntil is before validFrom in the MSO of the credential`() {
            // validFrom is chronologically after validUntil even though neither is future/past by itself
            every { DateUtils.parseDate("2026-10-23T07:01:17Z") } returns Date(1792738877000L)
            every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)

            val mso = buildMso(
                validFrom = taggedDate("2026-10-23T07:01:17Z"),
                validUntil = taggedDate("2024-10-23T07:01:17Z"),
                signed = taggedDate("2026-10-23T07:01:17Z")
            )
            val credential = buildMdocCredential(mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                validatorAt(AFTER_WINDOW).validate(credential)
            }

            assertEquals(ERROR_MESSAGE_INVALID_DATE_MSO, verificationException.errorMessage)
            assertEquals(ERROR_CODE_INVALID_DATE_MSO, verificationException.errorCode)
        }

        @Test
        fun `should throw ERR_INVALID_DATE_MSO not soft expiry when inverted window is fully in the past`() {
            // Both dates past; validUntil before validFrom. Ordering must fail hard before ERR_VC_EXPIRED.
            every { DateUtils.parseDate("2023-10-23T07:01:17Z") } returns Date(1698044477000L)
            every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)

            val mso = buildMso(
                validFrom = taggedDate("2024-10-23T07:01:17Z"),
                validUntil = taggedDate("2023-10-23T07:01:17Z"),
                signed = taggedDate("2024-10-23T07:01:17Z")
            )
            val credential = buildMdocCredential(mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                validatorAt(AFTER_WINDOW).validate(credential)
            }

            assertEquals(ERROR_MESSAGE_INVALID_DATE_MSO, verificationException.errorMessage)
            assertEquals(ERROR_CODE_INVALID_DATE_MSO, verificationException.errorCode)
        }

        @ParameterizedTest(name = "shape {0}")
        @ValueSource(strings = ["A", "B", "C"])
        fun `should throw exception when validFrom is before signed`(shape: String) {
            every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)
            every { DateUtils.parseDate("2025-10-23T07:01:17Z") } returns Date(1761202877000L)
            every { DateUtils.parseDate("2026-10-23T07:01:17Z") } returns Date(1792738877000L)

            // validFrom (2024) predates signed (2025) - checked for every shape
            val mso = buildMso(
                validFrom = taggedDate("2024-10-23T07:01:17Z"),
                validUntil = taggedDate("2026-10-23T07:01:17Z"),
                signed = taggedDate("2025-10-23T07:01:17Z")
            )
            val credential = buildCredential(shape, mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                validatorAt("2026-01-01T00:00:00Z").validate(credential)
            }

            assertEquals(ERROR_MESSAGE_VALID_FROM_BEFORE_SIGNED_MSO, verificationException.errorMessage)
            assertEquals(ERROR_CODE_INVALID_VALID_FROM_MSO, verificationException.errorCode)
        }

        @ParameterizedTest(name = "shape {0}")
        @ValueSource(strings = ["A", "B", "C"])
        fun `should return true when validFrom equals signed`(shape: String) {
            every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)
            every { DateUtils.parseDate("2026-10-23T07:01:17Z") } returns Date(1792738877000L)

            // validFrom equals signed - boundary case, must pass since the rule is validFrom >= signed
            val mso = buildMso(
                validFrom = taggedDate("2024-10-23T07:01:17Z"),
                validUntil = taggedDate("2026-10-23T07:01:17Z"),
                signed = taggedDate("2024-10-23T07:01:17Z")
            )
            val credential = buildCredential(shape, mso)

            val isVerified = validatorAt(IN_WINDOW).validate(credential)

            assertTrue(isVerified)
        }

        @Test
        fun `should throw when validFrom is a future date in the latest MSO structure`() {
            every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)
            every { DateUtils.parseDate("2026-10-23T07:01:17Z") } returns Date(1792738877000L)
            every { DateUtils.parseDate("2028-10-23T07:01:17Z") } returns Date(1856156477000L)

            val mso = buildMso(
                validFrom = taggedDate("2026-10-23T07:01:17Z"),
                validUntil = taggedDate("2028-10-23T07:01:17Z"),
                signed = taggedDate("2024-10-23T07:01:17Z")
            )
            val credential = buildMdocCredential(mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                validatorAt(IN_WINDOW).validate(credential)
            }

            assertEquals(ERROR_CURRENT_DATE_BEFORE_VALID_FROM, verificationException.errorMessage)
            assertEquals(ERROR_CODE_CURRENT_DATE_BEFORE_VALID_FROM, verificationException.errorCode)
        }

        @ParameterizedTest(name = "version {0} is accepted")
        @ValueSource(strings = ["1.0", "1.1"])
        fun `should accept MSO version with major 1`(version: String) {
            val mso = buildMso().apply { put(UnicodeString("version"), UnicodeString(version)) }
            assertTrue(validatorAt(IN_WINDOW).validate(buildMdocCredential(mso)))
        }

        @ParameterizedTest(name = "version {0} is rejected")
        @ValueSource(strings = ["2.0", "0.9", "1", "01.0", "1.abc", "1.0.0", "number"])
        fun `should reject MSO version that is not major 1 dot minor`(version: String) {
            val versionItem: DataItem =
                if (version == "number") UnsignedInteger(1) else UnicodeString(version)
            val mso = buildMso().apply { put(UnicodeString("version"), versionItem) }

            val verificationException = assertThrows(ValidationException::class.java) {
                validatorAt(IN_WINDOW).validate(buildMdocCredential(mso))
            }

            assertEquals(ERROR_MESSAGE_INVALID_MSO_VERSION, verificationException.errorMessage)
            assertEquals(ERROR_CODE_INVALID_MSO_VERSION, verificationException.errorCode)
        }

        @Test
        fun `should reject a missing MSO version`() {
            val mso = buildMso().apply { remove(UnicodeString("version")) }
            val verificationException = assertThrows(ValidationException::class.java) {
                validatorAt(IN_WINDOW).validate(buildMdocCredential(mso))
            }
            assertEquals(ERROR_CODE_INVALID_MSO, verificationException.errorCode)
        }

        @ParameterizedTest(name = "digestAlgorithm {0} is accepted")
        @ValueSource(strings = ["SHA-256", "SHA-384", "SHA-512"])
        fun `should accept supported digestAlgorithm`(digestAlgorithm: String) {
            val mso = buildMso().apply { put(UnicodeString("digestAlgorithm"), UnicodeString(digestAlgorithm)) }
            assertTrue(validatorAt(IN_WINDOW).validate(buildMdocCredential(mso)))
        }

        @ParameterizedTest(name = "digestAlgorithm {0} is rejected")
        @ValueSource(strings = ["MD5", "SHA-1", "SHA-224", "sha-256"])
        fun `should throw when digestAlgorithm is unsupported`(digestAlgorithm: String) {
            val mso = buildMso().apply { put(UnicodeString("digestAlgorithm"), UnicodeString(digestAlgorithm)) }

            val verificationException = assertThrows(ValidationException::class.java) {
                validatorAt(IN_WINDOW).validate(buildMdocCredential(mso))
            }

            assertEquals(ERROR_MESSAGE_INVALID_DIGEST_ALGORITHM, verificationException.errorMessage)
            assertEquals(ERROR_CODE_INVALID_DIGEST_ALGORITHM, verificationException.errorCode)
        }

        @Test
        fun `should reject a missing digestAlgorithm`() {
            val mso = buildMso().apply { remove(UnicodeString("digestAlgorithm")) }
            val verificationException = assertThrows(ValidationException::class.java) {
                validatorAt(IN_WINDOW).validate(buildMdocCredential(mso))
            }
            assertEquals(ERROR_CODE_INVALID_MSO, verificationException.errorCode)
        }

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = ["signed", "validFrom", "validUntil", "expectedUpdate"])
        fun `should reject a validityInfo date that is not YYYY-MM-DDThh-mm-ssZ`(field: String) {
            val base = mapOf(
                "signed" to "2024-10-23T07:01:17",
                "validFrom" to "2024-10-23T07:01:17",
                "validUntil" to "2026-10-23T07:01:17",
                "expectedUpdate" to "2025-10-23T07:01:17",
            ).getValue(field)
            val shiftedTo0530 = java.time.OffsetDateTime.parse("${base}Z")
                .withOffsetSameInstant(java.time.ZoneOffset.ofHoursMinutes(5, 30))
                .format(java.time.format.DateTimeFormatter.ISO_OFFSET_DATE_TIME)
            listOf("$base.0Z", "$base+00:00", shiftedTo0530, base, "2024-02-30T00:00:00Z").forEach { value ->
                val exception = assertThrows(ValidationException::class.java, {
                    validatorAt(IN_WINDOW).validate(buildMdocCredential(msoWithDate(field, value)))
                }, "$field = $value")
                assertTrue(exception.errorCode.isNotEmpty(), "$field = $value")
            }
            assertTrue(validatorAt(IN_WINDOW).validate(buildMdocCredential(msoWithDate(field, "${base}Z"))))
        }

        private fun msoWithDate(field: String, value: String): Map = when (field) {
            "signed" -> buildMso(signed = taggedDate(value))
            "validFrom" -> buildMso(validFrom = taggedDate(value))
            "validUntil" -> buildMso(validUntil = taggedDate(value))
            else -> buildMso(expectedUpdate = taggedDate(value))
        }

        @ParameterizedTest(name = "shape {0}")
        @ValueSource(strings = ["A", "B", "C"])
        fun `should reject an untagged validFrom in every shape`(shape: String) {
            val mso = buildMso(validFrom = UnicodeString("2024-10-23T07:01:17Z"))
            val exception = assertThrows(ValidationException::class.java) {
                validatorAt(IN_WINDOW).validate(buildCredential(shape, mso))
            }
            assertEquals("Invalid validityInfo - validFrom is not in date format", exception.errorMessage)
            assertEquals(ERROR_CODE_INVALID_VALIDITY_INFO, exception.errorCode)
        }

        @Test
        fun `should throw when validityInfo date has fractional seconds`() {

            val mso = buildMso(validFrom = taggedDate("2024-10-23T07:01:17.500Z"))
            val credential = buildMdocCredential(mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                validatorAt(IN_WINDOW).validate(credential)
            }

            assertTrue(verificationException.errorMessage.startsWith(ERROR_MESSAGE_INVALID_MSO_DATE_FORMAT))
            assertEquals(ERROR_CODE_INVALID_MSO_DATE_FORMAT, verificationException.errorCode)
        }

        @Test
        fun `should throw exception when validityInfo-expectedUpdate value is not a valid date`() {
            every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)
            every { DateUtils.parseDate("2026-10-23T07:01:17Z") } returns Date(1792738877000L)
            every { DateUtils.parseDate("not-a-real-date") } returns null

            // expectedUpdate is tagged correctly as tdate (tag 0) but its value doesn't parse as a valid date
            val mso = buildMso(expectedUpdate = taggedDate("not-a-real-date"))
            val credential = buildMdocCredential(mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                MsoMdocValidator().validate(credential)
            }

            assertEquals(ERROR_MESSAGE_INVALID_EXPECTED_UPDATE_MSO, verificationException.errorMessage)
            assertEquals(ERROR_CODE_INVALID_VALIDITY_INFO, verificationException.errorCode)
        }
    }

    @Nested
    @DisplayName("MSO Mandatory Field Structural Validation Tests")
    inner class MsoMandatoryFieldValidation {

        @ParameterizedTest(name = "should throw when mandatory field \"{0}\" is not available in MSO")
        @ValueSource(strings = ["version", "digestAlgorithm", "valueDigests", "deviceKeyInfo", "docType", "validityInfo"])
        fun `should throw exception when a mandatory field is not available in MSO`(mandatoryField: String) {
            val mso = buildMso().apply { remove(UnicodeString(mandatoryField)) }
            val credential = buildMdocCredential(mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                MsoMdocValidator().validate(credential)
            }

            assertEquals(
                "$mandatoryField is not available in MSO which is expected",
                verificationException.errorMessage
            )
            assertEquals(ERROR_CODE_INVALID_MSO, verificationException.errorCode)
        }

        @Test
        fun `should throw exception when validityInfo is not a map in the credential's MSO`() {
            // validityInfo is present but is a plain string instead of the expected map/object
            val mso = buildMso().apply {
                put(UnicodeString("validityInfo"), UnicodeString("not-a-map"))
            }
            val credential = buildMdocCredential(mso)

            val verificationException = assertThrows(ValidationException::class.java) {
                MsoMdocValidator().validate(credential)
            }

            assertEquals(
                "validityInfo is not available in MSO which is expected",
                verificationException.errorMessage
            )
            assertEquals(ERROR_CODE_INVALID_MSO, verificationException.errorCode)
        }
    }

    @Nested
    @DisplayName("Clock tolerance boundaries")
    inner class ClockToleranceBoundaries {
        private val validFrom = "2024-10-23T07:01:17Z"
        private val validUntil = "2026-10-23T07:01:17Z"
        private val credential = buildMdocCredential(buildMso())

        @Test
        fun `should pass when validFrom and signed are just inside the future tolerance`() {
            // signed == validFrom == 2024-10-23T07:01:17Z
            val now = millis(validFrom) - MDOC_CLOCK_SKEW_TOLERANCE_MS
            assertTrue(validatorAt(now).validate(credential))
        }

        @Test
        fun `should fail signed in future when just outside the tolerance`() {
            // validFrom stays inside the tolerance; signed is one millisecond outside it.
            val signedLater = buildMso(
                validFrom = taggedDate("2025-01-01T00:00:00Z"),
                signed = taggedDate("2025-01-01T00:00:01Z"),
            )
            val now = millis("2025-01-01T00:00:01Z") - MDOC_CLOCK_SKEW_TOLERANCE_MS - 1
            val exception = assertThrows(ValidationException::class.java) {
                validatorAt(now).validate(buildMdocCredential(signedLater))
            }
            assertEquals(ERROR_CODE_INVALID_VALIDITY_INFO_MSO, exception.errorCode)
        }

        @Test
        fun `should fail validFrom in future when just outside the tolerance`() {
            val laterValidFrom = "2025-01-01T00:00:00Z"
            val mso = buildMso(validFrom = taggedDate(laterValidFrom))
            val now = millis(laterValidFrom) - MDOC_CLOCK_SKEW_TOLERANCE_MS - 1
            val exception = assertThrows(ValidationException::class.java) {
                validatorAt(now).validate(buildMdocCredential(mso))
            }
            assertEquals(ERROR_CODE_CURRENT_DATE_BEFORE_VALID_FROM, exception.errorCode)
        }

        @Test
        fun `should pass validFrom just inside the tolerance`() {
            val laterValidFrom = "2025-01-01T00:00:00Z"
            val mso = buildMso(validFrom = taggedDate(laterValidFrom))
            val now = millis(laterValidFrom) - MDOC_CLOCK_SKEW_TOLERANCE_MS
            assertTrue(validatorAt(now).validate(buildMdocCredential(mso)))
        }

        @Test
        fun `should not be expired exactly at validUntil or just inside the tolerance`() {
            assertTrue(validatorAt(millis(validUntil)).validate(credential))
            assertTrue(validatorAt(millis(validUntil) + MDOC_CLOCK_SKEW_TOLERANCE_MS).validate(credential))
        }

        @Test
        fun `should be expired just outside the tolerance after validUntil`() {
            val now = millis(validUntil) + MDOC_CLOCK_SKEW_TOLERANCE_MS + 1
            val exception = assertThrows(ValidationException::class.java) {
                validatorAt(now).validate(credential)
            }
            assertEquals(ERROR_CODE_VC_EXPIRED, exception.errorCode)
        }
    }

    @Nested
    @DisplayName("signed is mandatory for every shape")
    inner class SignedMandatory {
        @Test
        fun `should fail legacy shape B credential without signed`() {
            val credential = buildLegacyMdocCredential(buildMso(includeSigned = false))
            val exception = assertThrows(ValidationException::class.java) {
                validatorAt(IN_WINDOW).validate(credential)
            }
            assertEquals(ERROR_CODE_INVALID_DATE_MSO, exception.errorCode)
        }

        @Test
        fun `should fail latest shape A credential without signed`() {
            val credential = buildMdocCredential(buildMso(includeSigned = false))
            val exception = assertThrows(ValidationException::class.java) {
                validatorAt(IN_WINDOW).validate(credential)
            }
            assertEquals(ERROR_CODE_INVALID_DATE_MSO, exception.errorCode)
        }

        @Test
        fun `should pass legacy shape B credential with signed`() {
            val credential = buildLegacyMdocCredential(buildMso())
            assertTrue(validatorAt(IN_WINDOW).validate(credential))
        }
    }

    @Nested
    @DisplayName("valueDigests ISO layout")
    inner class ValueDigestsLayout {
        private fun msoWithValueDigests(valueDigests: DataItem) =
            buildMso().apply { put(UnicodeString("valueDigests"), valueDigests) }

        private fun assertInvalidLayout(valueDigests: DataItem) {
            val exception = assertThrows(ValidationException::class.java) {
                validatorAt(IN_WINDOW).validate(buildMdocCredential(msoWithValueDigests(valueDigests)))
            }
            assertEquals(ERROR_MESSAGE_INVALID_VALUE_DIGESTS_STRUCTURE, exception.errorMessage)
            assertEquals(ERROR_CODE_INVALID_MSO, exception.errorCode)
        }

        @Test
        fun `should accept namespace to map of uint to bstr`() {
            val valueDigests = Map().apply {
                put(UnicodeString("org.iso.18013.5.1"), Map().apply {
                    put(UnsignedInteger(0), ByteString(ByteArray(32)))
                })
            }
            assertTrue(validatorAt(IN_WINDOW).validate(buildMdocCredential(msoWithValueDigests(valueDigests))))
        }

        @Test
        fun `should reject non-ISO nameSpaces wrapper`() {
            assertInvalidLayout(Map().apply {
                put(UnicodeString("nameSpaces"), Map().apply {
                    put(UnicodeString("org.iso.18013.5.1"), Map().apply {
                        put(UnsignedInteger(0), ByteString(ByteArray(32)))
                    })
                })
            })
        }

        @Test
        fun `should reject valueDigests that is not a map`() {
            assertInvalidLayout(UnicodeString("not-a-map"))
        }

        @Test
        fun `should reject non-text namespace key`() {
            assertInvalidLayout(Map().apply {
                put(UnsignedInteger(1), Map())
            })
        }

        @Test
        fun `should reject non-uint digestID key`() {
            assertInvalidLayout(Map().apply {
                put(UnicodeString("org.iso.18013.5.1"), Map().apply {
                    put(UnicodeString("0"), ByteString(ByteArray(32)))
                })
            })
        }

        @Test
        fun `should reject an MSO digestID key of 2^31 or above`() {
            val exception = assertThrows(ValidationException::class.java) {
                validatorAt(IN_WINDOW).validate(
                    buildMdocCredential(msoWithValueDigests(Map().apply {
                        put(UnicodeString("org.iso.18013.5.1"), Map().apply {
                            put(UnsignedInteger(java.math.BigInteger.ONE.shiftLeft(31)), ByteString(ByteArray(32)))
                        })
                    }))
                )
            }
            assertEquals(ERROR_MESSAGE_INVALID_MSO_DIGEST_ID, exception.errorMessage)
            assertEquals(ERROR_CODE_INVALID_MSO, exception.errorCode)
        }

        @Test
        fun `should accept an MSO digestID key of 2^31 - 1`() {
            val valueDigests = Map().apply {
                put(UnicodeString("org.iso.18013.5.1"), Map().apply {
                    put(
                        UnsignedInteger(java.math.BigInteger.ONE.shiftLeft(31).subtract(java.math.BigInteger.ONE)),
                        ByteString(ByteArray(32))
                    )
                })
            }
            assertTrue(validatorAt(IN_WINDOW).validate(buildMdocCredential(msoWithValueDigests(valueDigests))))
        }

        @Test
        fun `should reject non-bstr digest value`() {
            assertInvalidLayout(Map().apply {
                put(UnicodeString("org.iso.18013.5.1"), Map().apply {
                    put(UnsignedInteger(0), UnicodeString("digest"))
                })
            })
        }
    }
}
