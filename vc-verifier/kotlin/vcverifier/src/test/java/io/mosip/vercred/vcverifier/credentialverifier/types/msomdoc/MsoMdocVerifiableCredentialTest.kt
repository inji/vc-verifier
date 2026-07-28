package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MSO
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.DateUtils
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.Date

private const val MSO_TAG24 = 24L

private fun encode(dataItem: DataItem): ByteArray =
    ByteArrayOutputStream().also { CborEncoder(it).encode(dataItem) }.toByteArray()

private fun toBase64Url(bytes: ByteArray): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

/**
 * Builds a minimal MSO map. Only [docType] is populated since [MsoMdocVerifiableCredential.parse]
 * only reads the docType field directly; the rest of the mandatory-field validation is
 * MsoMdocValidator's responsibility and is out of scope here.
 */
private fun buildMso(docType: String? = "org.iso.18013.5.1.mDL"): Map =
    Map().apply {
        if (docType != null) put(UnicodeString(DOC_TYPE), UnicodeString(docType))
        put(UnicodeString("version"), UnicodeString("1.0"))
    }

/**
 * Builds an issuerAuth COSE_Sign1-like array: [protectedHeaders, unprotectedHeaders, payload, signature].
 *
 * @param mso the MSO map to embed as the (tag-24-wrapped) payload; when null, a byte string that fails
 * to decode as CBOR is used instead to simulate a corrupt payload.
 * @param tagPayload whether the inner MSO byte string is wrapped with CBOR tag 24, as required by spec.
 */
private fun buildIssuerAuth(mso: Map?, tagPayload: Boolean = true): Array {
    val payloadBytes: ByteArray = if (mso == null) {
        // 0xBB signals a CBOR map whose 8-byte length header is truncated, causing a genuine decode failure
        byteArrayOf(0xBB.toByte())
    } else {
        val msoBytes = ByteString(encode(mso)).apply { if (tagPayload) setTag(MSO_TAG24) }
        encode(msoBytes)
    }

    return Array().apply {
        add(ByteString(ByteArray(0)))
        add(Map())
        add(ByteString(payloadBytes))
        add(ByteString(ByteArray(4)))
    }
}

private fun buildLatestCredential(issuerAuth: Array, namespaces: Map = Map()): String {
    val credential = Map().apply {
        put(UnicodeString("issuerAuth"), issuerAuth)
        put(UnicodeString("nameSpaces"), namespaces)
    }
    return toBase64Url(encode(credential))
}

private fun buildLegacyIssuerSignedCredential(
    issuerAuth: Array,
    namespaces: Map = Map(),
    docType: String = "org.iso.18013.5.1.mDL"
): String {
    val issuerSigned = Map().apply {
        put(UnicodeString("issuerAuth"), issuerAuth)
        put(UnicodeString("nameSpaces"), namespaces)
    }
    val credential = Map().apply {
        put(UnicodeString("docType"), UnicodeString(docType))
        put(UnicodeString("issuerSigned"), issuerSigned)
    }
    return toBase64Url(encode(credential))
}

private fun buildLegacyDocumentsCredential(
    issuerAuth: Array,
    namespaces: Map = Map(),
    docType: String = "org.iso.18013.5.1.mDL"
): String {
    val issuerSigned = Map().apply {
        put(UnicodeString("issuerAuth"), issuerAuth)
        put(UnicodeString("nameSpaces"), namespaces)
    }
    val document = Map().apply {
        put(UnicodeString("docType"), UnicodeString(docType))
        put(UnicodeString("issuerSigned"), issuerSigned)
    }
    val credential = Map().apply {
        put(UnicodeString("documents"), Array().apply { add(document) })
    }
    return toBase64Url(encode(credential))
}

class MsoMdocVerifiableCredentialTest {

    @AfterEach
    fun tearDown() {
        clearAllMocks()
    }

    // Credential verification and validation
    @Test
    fun `should validate and verify valid mDocs successfully`() {
        mockkObject(DateUtils)
        every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)
        every { DateUtils.parseDate("2026-10-23T07:01:17Z") } returns Date(1792738877000L)

        val validMDocs = listOf(
            // VCI 1.0 compliant
            "omppc3N1ZXJBdXRohEOhASahGCFZAxQwggMQMIIB-KADAgECAggGru5Xjrda-DANBgkqhkiG9w0BAQsFADB4MQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9SRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMR8wHQYDVQQDDBZ3d3cuZXhhbXBsZS5jb20gKFJPT1QpMB4XDTI2MDcxMzA2MzY0NloXDTI5MDcxMjA2MzY0NlowgZsxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxQjBABgNVBAMMOXd3dy5leGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VDX1IxLUVDX1NFQ1AyNTZSMV9TSUdOKTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCxNsdJnJDCpzS-oiskMiAXKts0KfSq0bKAcAF9AIVcylo234k6c5ze6zd-LYUq4qZt2Epj0JtzVJzWtXJBmy5-jRTBDMBIGA1UdEwEB_wQIMAYBAf8CAQEwHQYDVR0OBBYEFNTUxJGN9cvnw0bkpOY7hXCOgEIgMA4GA1UdDwEB_wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEAdCMKCVQqQFNuXfZVD2JrmGHMdqmBsyEITavF8uIjOUu39qaaXyhvLeCggP7PjXJ8Cu141VKCkj6XHtvHM5iqCQsAQpjgzp6Hi27sau_yKLOOKBz8E2G9N9-skn9UiVJqSeZLOl_gRcPhbxVndQp7FZ4cdct4r_kObVt-W-BTlDJWjz54bPVhInnFfLpv2KlSqASRBIpbasMehVaYR7E9Rq_Ya5Ms5A8MYzXzdLeBdSWJCIyxmHasTax6cVM5GdqpAOjbJF_7k7X4JHBEIiDrJ_O0p9zwpBWdAn_Kb-oCe3VQHzrmeCsp2uyNRvzEqJ5Yd5b26-V8C8yBj7P7Uaa-PlkCUNgYWQJLpmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB4GzIwMjYtMDctMjBUMDQ6NDc6NDIuNzE2OTA5Wml2YWxpZEZyb23AeBsyMDI2LTA3LTIwVDA0OjQ3OjQyLjcxNjkwOVpqdmFsaWRVbnRpbMB4GDIwMjgtMDctMjBUMDQ6NDc6NDIuNzE3Wmx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xpgBYILcu1K9SpiobtelCZX5_BHQrOJCCoaXtJCGX35eeFnQSAVggApvPGQYz3DLYRbetDpT0-31okQ5uzWRwzrff00yMD7oCWCD4d3HGgi-70QBlGoiU5nggSPzpSI5GkxXdsOyG4ArVLgNYIOQbLhdNqN_8kCZzqVswmMeQ6MtpvttlT16uBgWMKdFyBFgg_hMVI7VctilrrgdQPGCdIEL4VgkVVaEMEvKcIY_xJKUFWCAtv66ml2lD15WYUUzAS6gJYj1DALcrbw9xjFFrZkhUuG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmmAQICWCtlNjVnMnVDNmJCMEREZGZNRzhTYlZ2TDFNSWxSNENxcGRoUWE4YmZQUDNVAyYgASFYILQicKMUp8767SCHDrTO6yWjmAm-WIjudd3pRo_zI7myIlggPBprbay4iRPtNiVtbVob_u3AQxpRmqWQSup7zPyNuLlvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZYQBCVJ3YkZ1ETAuhULd1ZGTv6ONhH_NsP61FIfpe69uLWEBThcUiJq7y_KRMms9KVi7pYcU3WhiNlOUC6hSYrB_1qbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGG2BhYZaRmcmFuZG9tWBiq53HDBUk9X9igBaZDmBelpFQndR2-nl9oZGlnZXN0SUQAbGVsZW1lbnRWYWx1ZW0ke2ZhbWlseU5hbWV9cWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1l2BhYY6RmcmFuZG9tWBgvL1T9pXgeuDdhIpe9VL0dEFL8IXB5rkJoZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZWwke2dpdmVuTmFtZX1xZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWGOkZnJhbmRvbVgYMuPQgcDhX9FgtaLBg5aC2SmZpPPsyUYlaGRpZ2VzdElEAmxlbGVtZW50VmFsdWVsJHtiaXJ0aERhdGV9cWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGXYGFhepGZyYW5kb21YGG9QaSwv6jAPrlLBDqMcpymi-NiA9MEChGhkaWdlc3RJRANsZWxlbWVudFZhbHVlYklOcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWG2kZnJhbmRvbVgYKA4VkRJdH22UPLypb9bl72lXGuja-E2xaGRpZ2VzdElEBGxlbGVtZW50VmFsdWVxJHtkb2N1bWVudE51bWJlcn1xZWxlbWVudElkZW50aWZpZXJvZG9jdW1lbnRfbnVtYmVy2BhYYKRmcmFuZG9tWBhb4Thi6agJuh0LXOhY3pRuffpIZgeZq9xoZGlnZXN0SUQFbGVsZW1lbnRWYWx1ZWske3BvcnRyYWl0fXFlbGVtZW50SWRlbnRpZmllcmhwb3J0cmFpdA",
            "uQACam5hbWVTcGFjZXOib29yZy5pc28uMjMyMjAuMYXYGFhspGhkaWdlc3RJRABxZWxlbWVudElkZW50aWZpZXJqaXNzdWVfZGF0ZWxlbGVtZW50VmFsdWXZA-xqMjAyNS0wMS0yOGZyYW5kb21YIErxfnTB6hOiIA04ICZ3yd-AuJ26dpcXlp8YuTgBM1yN2BhYbaRoZGlnZXN0SUQBcWVsZW1lbnRJZGVudGlmaWVya2V4cGlyeV9kYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDM0LTA4LTI4ZnJhbmRvbVgg_OZCKXTCt98EpyngHcPgZpZUOW7xklPYilJWdTE0BQPYGFhmpGhkaWdlc3RJRAJxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWJOTGZyYW5kb21YIL6jfi_BR7RpL5Yr__t-oyd8WmXJ_Q9TBIZzXtjUpY7x2BhYc6RoZGlnZXN0SUQDcWVsZW1lbnRJZGVudGlmaWVyeBlpc3N1aW5nX2F1dGhvcml0eV91bmljb2RlbGVsZW1lbnRWYWx1ZWRGaW1lZnJhbmRvbVgg0nFVdYSYfhAEiniI2Wd8UBj8h4QXlOCgf-QQIQvEBezYGFhupGhkaWdlc3RJRARxZWxlbWVudElkZW50aWZpZXJvZG9jdW1lbnRfbnVtYmVybGVsZW1lbnRWYWx1ZWowMTIzNDU2Nzg5ZnJhbmRvbVgghUJWGs3zVkR5RBXjc9SRIRzjKoLKtfnN-NQgGf28nhlub3JnLmlzby43MzY3LjGQ2BhYbKRoZGlnZXN0SUQAcWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVl2QPsajIwMjUtMDEtMjhmcmFuZG9tWCAQK1JdDqGeoW_k1hSgif2_OM4jGICEFrwxHfYYyO78C9gYWG2kaGRpZ2VzdElEAXFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZWxlbGVtZW50VmFsdWXZA-xqMjAzNC0wOC0yOGZyYW5kb21YIC15QwiKpul2vNwQ5Z2FdMY39miUMoRj1IdcVemp7J0p2BhYZqRoZGlnZXN0SUQCcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyeWxlbGVtZW50VmFsdWViTkxmcmFuZG9tWCDEDePMqiuu5O9lcZUQpOYwXbsQVAis8noW4I5bpm-Ao9gYWHOkaGRpZ2VzdElEA3FlbGVtZW50SWRlbnRpZmllcngZaXNzdWluZ19hdXRob3JpdHlfdW5pY29kZWxlbGVtZW50VmFsdWVkRmltZWZyYW5kb21YIP7xaybfvXtpejSlB1VqWwllBydC9GbH3Cl_vbYjThtU2BhYbqRoZGlnZXN0SUQEcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVqMDEyMzQ1Njc4OWZyYW5kb21YIPJA5tKANspHhq4760sB_Cjhtp7a5d9_PkXNQf8dGbcW2BhYbqRoZGlnZXN0SUQFcWVsZW1lbnRJZGVudGlmaWVyc3JlZ2lzdHJhdGlvbl9udW1iZXJsZWxlbWVudFZhbHVlZjExTU0wNWZyYW5kb21YIAB7l5XRkRffvEYK8PNZKeb2F5eCJTMMW48tiDuaozl-2BhYfqRoZGlnZXN0SUQGcWVsZW1lbnRJZGVudGlmaWVydGRhdGVfb2ZfcmVnaXN0cmF0aW9ubGVsZW1lbnRWYWx1ZcB0MjAyMS0xMi0yMFQxNzo0NTowMFpmcmFuZG9tWCAX_0vWuwnTpUMegYqwg3boCCZYMbSrVp6uDKcdYK3fbtgYWHqkaGRpZ2VzdElEB3FlbGVtZW50SWRlbnRpZmllcngaZGF0ZV9vZl9maXJzdF9yZWdpc3RyYXRpb25sZWxlbWVudFZhbHVlajIwMjAtMDctMTRmcmFuZG9tWCAps-PWQppAuUo7uscn2EUSjAFOe5s6VwSvohD-OjExFtgYWH-kaGRpZ2VzdElECHFlbGVtZW50SWRlbnRpZmllcngddmVoaWNsZV9pZGVudGlmaWNhdGlvbl9udW1iZXJsZWxlbWVudFZhbHVlbFBEMDItNTAxNjg5MGZyYW5kb21YIBJYrNNvfFBTwcOmEqG3dk8EVze9fccuoyEGkBeS2Rw62BhY8KRoZGlnZXN0SUQJcWVsZW1lbnRJZGVudGlmaWVybnZlaGljbGVfaG9sZGVybGVsZW1lbnRWYWx1ZYG5AARzZmFtaWx5X25hbWVfdW5pY29kZXgZYmFyb24gVmFuIGRlciBDw6tybm9zbGrDqXJmYW1pbHlfbmFtZV9sYXRpbjF4GWJhcm9uIFZhbiBkZXIgQ8Orcm5vc2xqw6lyZ2l2ZW5fbmFtZV91bmljb2RlY0NCQXFnaXZlbl9uYW1lX2xhdGluMWNDQkFmcmFuZG9tWCBp34-ABspkyViM6yfsS569XVruHuU_dtmQDJXpBJBUGNgYWMqkaGRpZ2VzdElECnFlbGVtZW50SWRlbnRpZmllcnJiYXNpY192ZWhpY2xlX2luZm9sZWxlbWVudFZhbHVluQAFdXZlaGljbGVfY2F0ZWdvcnlfY29kZWJNMXR0eXBlX2FwcHJvdmFsX251bWJlcmdlMS10ZXN0ZG1ha2VkT1BFTG9jb21tZXJjaWFsX25hbWVlTUlUU1VnY29sb3Vyc4IECWZyYW5kb21YIA4IOgJdyh4UHCGj3SuJF-E0ZGq6Ztwc3wMuiovKZkVf2BhYzaRoZGlnZXN0SUQLcWVsZW1lbnRJZGVudGlmaWVyaW1hc3NfaW5mb2xlbGVtZW50VmFsdWW5AAVkdW5pdGJrZ3gZdGVjaG5fcGVybV9tYXhfbGFkZW5fbWFzcxkFCnB2ZWhpY2xlX21heF9tYXNzGQR-dndob2xlX3ZlaGljbGVfbWF4X21hc3MZCcR1bWFzc19pbl9ydW5uaW5nX29yZGVyGQOYZnJhbmRvbVggrY7ZOa4ThtGv9SzVgJ37J9KPk3XcfWXC-BaaaprHg3jYGFjApGhkaWdlc3RJRAxxZWxlbWVudElkZW50aWZpZXJxdHJhaWxlcl9tYXNzX2luZm9sZWxlbWVudFZhbHVluQADZHVuaXRia2d4I3RlY2hfcGVybV9tYXhfdG93X21hc3NfYnJha2VkX3RyYWlsGQbWeCN0ZWNoX3Blcm1fbWF4X3Rvd19tYXNzX3VuYnJfdHJhaWxlchkBy2ZyYW5kb21YIAoqwh1CT6FCq4zpC7-PkeDboMx08WauVqxGxE1wuHp72BhYlKRoZGlnZXN0SUQNcWVsZW1lbnRJZGVudGlmaWVya2VuZ2luZV9pbmZvbGVsZW1lbnRWYWx1ZbkAA29lbmdpbmVfY2FwYWNpdHkZA-dsZW5naW5lX3Bvd2VyGDRtZW5lcmd5X3NvdXJjZYEPZnJhbmRvbVggHZb1NzpvgwZOm91cmkf2DDcwaUUl9kYa90Oc9Ta4-VTYGFiYpGhkaWdlc3RJRA5xZWxlbWVudElkZW50aWZpZXJsc2VhdGluZ19pbmZvbGVsZW1lbnRWYWx1ZbkAAnducl9vZl9zZWF0aW5nX3Bvc2l0aW9ucwV4GW51bWJlcl9vZl9zdGFuZGluZ19wbGFjZXMBZnJhbmRvbVggEuhRQXivy2P0TF2_Z2Pkm99CkI5k2nL72lEaKNWBSLTYGFhupGhkaWdlc3RJRA9xZWxlbWVudElkZW50aWZpZXJ2dW5fZGlzdGluZ3Vpc2hpbmdfc2lnbmxlbGVtZW50VmFsdWVjTkxEZnJhbmRvbVggagyXDtjE36sSTawTchag-yb29HtI8cYqW-bK0UKUruFqaXNzdWVyQXV0aIRDoQEmogRYMXpEbmFlUnNqTURGTHBmcVZXZ2lqb1JQczhNb1RHOVpVRlBBRlZ1emo5cm5wd1d1OHoYIVkB6TCCAeUwggGLoAMCAQICEBlHRdJAYkBg2sKftHQUkuYwCgYIKoZIzj0EAwIwHTEOMAwGA1UEAxMFQW5pbW8xCzAJBgNVBAYTAk5MMB4XDTI1MDQxMjE0MjMzMFoXDTI2MDUwMjE0MjMzMFowITESMBAGA1UEAxMJY3JlZG8gZGNzMQswCQYDVQQGEwJOTDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBV1TQNJWmvuT9p5OTyRaL_MYQRTc-VDiQSFbMpNEikn6k3yjAekfnBQzYo3ZgWMrhGlIDILlHPITlZ563lvbYSjgagwgaUwHQYDVR0OBBYEFGEfLxUE5ZI39fzZynmcb2NGc92gMA4GA1UdDwEB_wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMB8GA1UdIwQYMBaAFC_fMGjWL_UJ8SB2-QhYMY72VLVLMCEGA1UdEgQaMBiGFmh0dHBzOi8vZnVua2UuYW5pbW8uaWQwGQYDVR0RBBIwEIIOZnVua2UuYW5pbW8uaWQwCgYIKoZIzj0EAwIDSAAwRQIgQcHUv3BQbN2sLXz_RhVZIEjiE0HTwTC4bCQco4O5di0CIQD0CVsu6kLH6thq3aXBlx6w1StMP15zxdlwE-q01_Lgj1kET9gYWQRKuQAGZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2bHZhbHVlRGlnZXN0c6Jvb3JnLmlzby4yMzIyMC4xpQBYIB2G4hDSeswt4Rq6ydeZylDfRDAWiYspdkidAE7Yb4qBAVggyIgiR5fGfOdnpM4Ji2id2ZpD2QMS_Tengis6rel1DPACWCDHGEHm4o0gAzk9D4RW9MUYCswWvJjvqydtvBvE-OQ5qANYILal7XhtLFFVV_kp5UQ_Zr6-f2sebkZpAGZNZY-ImJMjBFggzVJ5MdMc1SV5OwY03_Uy4mMn2yaPbREt1rrTEUibuOdub3JnLmlzby43MzY3LjGwAFggg2_eeMPRk3JlcBZ5AJe-KNHVWjAO6zkNy72SbDEsJzIBWCDTJAD9cCltZ_dNPxcqPCFMRJ3nwYua1UlpATpTNnzhiAJYIPFJFGZLA6l6PzstIBx60algbwrcF-mjS88n2nlEqXG1A1ggZZhaoyzv7daURZRlNyJigO93ZZrMuHnL7rmIDG-ShD0EWCBzU2BjNfa-7rRCsog_zxQjDQSyFTqOUdv1s0cxSp1E8gVYIAWp0nAnJc64-MfhtLc_6SdTNrwCayefbXaabn6ZXLj4BlggsZuWXhxG0cWNp5A3RXmwyUblUDKdW4JF2VGON7pX4FkHWCBirQK45XswEzjDyW2hYmKRk8SqM_5NxDAHzpNlYP2_LwhYIFUJT76s_Zg9seiKLoew4wZdJM9svs0TMreNKAH9klh1CVggqNmT3T1jaGBRYMUulr-KnygbpsyXhVzCXT10PJ0RWwcKWCDrVUbaRj7pUG0u7z1mOVNArA7VHOOOaEbc_v4Ol0YkQwtYIEwIjGdsKQzjVbbprpeip-WxrnqbuQIC3I49CIqwBTOIDFggmFHFoD4EugsXG-oJAcMQGY08lPDOaeul1ZNzY48pn0gNWCAflI9gHteg9U_kecDKKI21Vx4_7Vrus2X_U81B6wuODg5YIHY18e1l558_qlD3NcjSyCSMOWsNTwECCzjhDXLBFyCRD1gghsadql0BM096G4_cfvlnep6v5rlFXNhqnEaJC_NUbF5tZGV2aWNlS2V5SW5mb7kAAWlkZXZpY2VLZXmkAQIgASFYINrE_dpcUCKQWZa4Gs73VOPsrbFzFo0sdA9ba58hn2qpIlgg-xN3D4F3LOWlcM99l3Kn3KnxWtsd7wxO5e-KJfhuNhZnZG9jVHlwZXNvcmcuaXNvLjczNjcuMS5tVlJDbHZhbGlkaXR5SW5mb7kABGZzaWduZWTAdDIwMjUtMDEtMjhUMDA6MDA6MDBaaXZhbGlkRnJvbcB0MjAyNS0wMS0yOFQwMDowMDowMFpqdmFsaWRVbnRpbMB0MjAzNC0wOC0yOFQwMDowMDowMFpuZXhwZWN0ZWRVcGRhdGXAdDIwMjctMDEtMTNUMjA6MTg6MzVaWEBv-3sb9npMUov5sUU-IXyJ6LnJoLhQ_eyqqqxYyyWDGxlUA4ZMUMZ5m5JvJF1cEEZ6IYec5sTDm9Dr1LBfMI6Y",
            // Legacy structure
            "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkBxDCCAcAwggFloAMCAQICFH6lICTsAhkMivItOT9v6JeZubwmMAoGCCqGSM49BAMCME4xCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTERMA8GA1UEBwwITW9ja0NpdHkxDTALBgNVBAoMBE1vY2sxDTALBgNVBAsMBE1vY2swHhcNMjQxMDIyMDcwMjUwWhcNMjUxMDIyMDcwMjUwWjBOMQswCQYDVQQGEwJNSzEOMAwGA1UECAwFTUstS0ExETAPBgNVBAcMCE1vY2tDaXR5MQ0wCwYDVQQKDARNb2NrMQ0wCwYDVQQLDARNb2NrMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjtRcOXgIyR_xqGB-M6d0qkrjQWOBGGdlPgfIfb2xW0egZAVEz_55IXCofWaprRGxX7qQTlNAZyByniay2jzhR6MhMB8wHQYDVR0OBBYEFNqAHypQYcwWoeUfmMv4SbztomFvMAoGCCqGSM49BAMCA0kAMEYCIQDsgsz9wCa56ukpfyvq9371b5GhkSZb38G7xFofWgFtJwIhAKxACllIOtcleKETDFGa3araADjKd2isahQtXZwQmPr1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggd4bqGFzNwBXyzdGmeipRMfjTQKQuzs6nvM7Z1AXsFBQGWCCaGHxiAeoHvfCNpkG3XpGTTQ787Fg9f3R9UTvKGa0mqwNYICnPRqwtKq9fYqI0sR96Ha3151joEQb24VAzTK4jw8puAVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjNUMDc6MDE6MTdaaXZhbGlkRnJvbcB0MjAyNC0xMC0yM1QwNzowMToxN1pqdmFsaWRVbnRpbMB0MjAyNi0xMC0yM1QwNzowMToxN1pYQOkgtaSchZRTPO01AjYgnKBT9mgXG4NUWsp_W5pCxz5eyB6SIpL9lVYg3tPOkTfYggsVSgPO8ostvTXn7DsBRl5qbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYWKRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVlajIwMjQtMTAtMjPYGFhZpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVlajIwMjktMTAtMjPYGFifpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyNC0xMC0yMywgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwMjktMTAtMjN92BhYV6RoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVkMTIzM9gYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYk1L2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE="
        )
        val mdocVerifiableCredential = MsoMdocVerifiableCredential()
        validMDocs.forEach { validMDoc ->
            val (validationMessage, validationErrorCode) = mdocVerifiableCredential.validate(validMDoc)
            assertEquals("",validationMessage)
            assertEquals("",validationErrorCode)

            val isVerified = mdocVerifiableCredential.verify(validMDoc)
            assertTrue(isVerified)
        }
    }

    private val credentialParser = MsoMdocVerifiableCredential()

    @Nested
    @DisplayName("parse() - structural variants")
    inner class StructuralVariants {

        @Test
        fun `should parse latest OpenID4VCI 1_0 structure and mark isLatest true`() {
            val mso = buildMso(docType = "org.iso.18013.5.1.mDL")
            val issuerAuth = buildIssuerAuth(mso)
            val credential = buildLatestCredential(issuerAuth)

            val (decodedCredential, credentialData, isLatest) = credentialParser.parse(credential)

            assertTrue(isLatest)
            assertNotNull(decodedCredential)
            assertEquals("org.iso.18013.5.1.mDL", (credentialData.docType as UnicodeString).string)
            assertEquals(issuerAuth, credentialData.issuerSigned.issuerAuth)
            assertNotNull(credentialData.mso)
        }

        @Test
        fun `should parse legacy issuerSigned structure and mark isLatest false`() {
            val mso = buildMso(docType = "org.iso.18013.5.1.mDL")
            val issuerAuth = buildIssuerAuth(mso)
            val credential = buildLegacyIssuerSignedCredential(issuerAuth)

            val (_, credentialData, isLatest) = credentialParser.parse(credential)

            assertFalse(isLatest)
            assertEquals("org.iso.18013.5.1.mDL", (credentialData.docType as UnicodeString).string)
        }

        @Test
        fun `should parse legacy documents-wrapped structure and mark isLatest false`() {
            val mso = buildMso(docType = "org.iso.18013.5.1.mDL")
            val issuerAuth = buildIssuerAuth(mso)
            val credential = buildLegacyDocumentsCredential(issuerAuth)

            val (_, credentialData, isLatest) = credentialParser.parse(credential)

            assertFalse(isLatest)
            assertEquals("org.iso.18013.5.1.mDL", (credentialData.docType as UnicodeString).string)
        }

        @Test
        fun `should return null docType when docType is absent from MSO`() {
            val mso = buildMso(docType = null)
            val issuerAuth = buildIssuerAuth(mso)
            val credential = buildLatestCredential(issuerAuth)

            val (_, credentialData, _) = credentialParser.parse(credential)

            assertNull(credentialData.docType)
        }

        @Test
        fun `should throw RuntimeException when neither documents, issuerSigned nor issuerAuth-nameSpaces structure is present`() {
            val credential = toBase64Url(encode(Map().apply { put(UnicodeString("foo"), UnicodeString("bar")) }))

            val exception = assertThrows(RuntimeException::class.java) {
                credentialParser.parse(credential)
            }

            assertEquals("Invalid issuerSigned structure in mDoc", exception.message)
        }

        @Test
        fun `should throw RuntimeException when issuerAuth is not an array`() {
            val issuerSigned = Map().apply {
                put(UnicodeString("issuerAuth"), UnicodeString("not-an-array"))
                put(UnicodeString("nameSpaces"), Map())
            }
            val credential = toBase64Url(encode(issuerSigned))

            val exception = assertThrows(RuntimeException::class.java) {
                credentialParser.parse(credential)
            }

            assertEquals("Invalid IssuerAuth structure in mDoc", exception.message)
        }
    }

    @Nested
    @DisplayName("parse() - decoding failures")
    inner class DecodingFailures {

        @Test
        fun `should throw RuntimeException when credential is not valid base64Url`() {
            val exception = assertThrows(RuntimeException::class.java) {
                credentialParser.parse("not-valid-base64url!!!")
            }

            assertTrue(exception.message!!.startsWith("Error on decoding base64Url encoded data"))
        }

        @Test
        fun `should throw RuntimeException when decoded bytes are not valid CBOR`() {
            // 0xBB signals a CBOR map whose 8-byte length header is truncated, causing a genuine decode failure
            val invalidCborBytes = byteArrayOf(0xBB.toByte())
            val credential = toBase64Url(invalidCborBytes)

            val exception = assertThrows(RuntimeException::class.java) {
                credentialParser.parse(credential)
            }

            assertTrue(exception.message!!.startsWith("Error on decoding CBOR encoded data"))
        }
    }

    @Nested
    @DisplayName("parse() - MSO payload validation")
    inner class MsoPayloadValidation {

        @Test
        fun `should throw ValidationException when mso payload is not tagged with 24`() {
            val mso = buildMso()
            val issuerAuth = buildIssuerAuth(mso, tagPayload = false)
            val credential = buildLatestCredential(issuerAuth)

            val exception = assertThrows(ValidationException::class.java) {
                credentialParser.parse(credential)
            }

            assertEquals("mso is not tagged", exception.errorMessage)
            assertEquals(ERROR_CODE_INVALID_MSO, exception.errorCode)
        }

        @Test
        fun `should accept legacy issuerSigned structure when mso payload is not tagged with 24`() {
            // The tag-24 requirement only applies to the latest OpenID4VCI 1.0 structure;
            // legacy docType-issuerSigned credentials are exempt from it.
            val mso = buildMso()
            val issuerAuth = buildIssuerAuth(mso, tagPayload = false)
            val credential = buildLegacyIssuerSignedCredential(issuerAuth)

            val (_, credentialData, isLatest) = credentialParser.parse(credential)

            assertFalse(isLatest)
            assertNotNull(credentialData.mso)
        }

        @Test
        fun `should throw ValidationException when issuerAuth payload is corrupt`() {
            val issuerAuth = buildIssuerAuth(mso = null)
            val credential = buildLatestCredential(issuerAuth)

            val exception = assertThrows(ValidationException::class.java) {
                credentialParser.parse(credential)
            }

            assertEquals("Invalid issuerAuth payload", exception.errorMessage)
            assertEquals(ERROR_CODE_INVALID_MSO, exception.errorCode)
        }
    }
}
