package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.mdl

import android.os.Build
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DS_CERT_EKU
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DS_CERT_KEY_USAGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DS_CERT_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUING_COUNTRY
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUING_JURISDICTION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MDL_ELEMENT
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerificationOptions
import io.mosip.vercred.vcverifier.credentialverifier.verifier.MsoMdocVerifier
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.BuildConfig
import org.bouncycastle.asn1.x509.KeyUsage
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import testutils.MdlEdgeCaseTestDataGenerator
import testutils.readClasspathFile
import java.time.Instant

/** Inside the validity of the real Certify fixture DS certificates (2026-07-13 .. 2029-07-12). */
private val CERTIFY_FIXTURE_NOW: Instant = Instant.parse("2026-08-01T00:00:00Z")

/** The missing-EKU fixture is signed 2026-10-14; its DS certificate expires 2028-12-10. */
private val MISSING_EKU_FIXTURE_NOW: Instant = Instant.parse("2027-01-01T00:00:00Z")

private fun optionsAt(now: Instant, strict: Boolean = true) =
    MsoMdocVerificationOptions(strictMdlProfile = strict, currentTimeMillis = { now.toEpochMilli() })

private fun verifierAt(now: Instant, strict: Boolean = true) = MsoMdocVerifier(optionsAt(now, strict))

/**
 * mDL checks that run after the signature and digests (MdlVerifier), exercised through
 * MsoMdocVerifier so the checks run on real signed credentials.
 */
class MdlVerifierTest {

    @BeforeEach
    fun setUp() {
        mockkObject(BuildConfig)
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O
    }

    @AfterEach
    fun after() {
        clearAllMocks()
    }

    @Test
    fun `should fail Certify fixtures whose DS certificate lacks the mDL EKU`() {
        val exception = assertThrows(ValidationException::class.java) {
            verifierAt(CERTIFY_FIXTURE_NOW).verify(
                "omppc3N1ZXJBdXRohEOhASahGCFZAxQwggMQMIIB-KADAgECAggGru5Xjrda-DANBgkqhkiG9w0BAQsFADB4MQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9SRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMR8wHQYDVQQDDBZ3d3cuZXhhbXBsZS5jb20gKFJPT1QpMB4XDTI2MDcxMzA2MzY0NloXDTI5MDcxMjA2MzY0NlowgZsxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxQjBABgNVBAMMOXd3dy5leGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VDX1IxLUVDX1NFQ1AyNTZSMV9TSUdOKTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCxNsdJnJDCpzS-oiskMiAXKts0KfSq0bKAcAF9AIVcylo234k6c5ze6zd-LYUq4qZt2Epj0JtzVJzWtXJBmy5-jRTBDMBIGA1UdEwEB_wQIMAYBAf8CAQEwHQYDVR0OBBYEFNTUxJGN9cvnw0bkpOY7hXCOgEIgMA4GA1UdDwEB_wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEAdCMKCVQqQFNuXfZVD2JrmGHMdqmBsyEITavF8uIjOUu39qaaXyhvLeCggP7PjXJ8Cu141VKCkj6XHtvHM5iqCQsAQpjgzp6Hi27sau_yKLOOKBz8E2G9N9-skn9UiVJqSeZLOl_gRcPhbxVndQp7FZ4cdct4r_kObVt-W-BTlDJWjz54bPVhInnFfLpv2KlSqASRBIpbasMehVaYR7E9Rq_Ya5Ms5A8MYzXzdLeBdSWJCIyxmHasTax6cVM5GdqpAOjbJF_7k7X4JHBEIiDrJ_O0p9zwpBWdAn_Kb-oCe3VQHzrmeCsp2uyNRvzEqJ5Yd5b26-V8C8yBj7P7Uaa-PlkCUNgYWQJLpmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB4GzIwMjYtMDctMjBUMDQ6NDc6NDIuNzE2OTA5Wml2YWxpZEZyb23AeBsyMDI2LTA3LTIwVDA0OjQ3OjQyLjcxNjkwOVpqdmFsaWRVbnRpbMB4GDIwMjgtMDctMjBUMDQ6NDc6NDIuNzE3Wmx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xpgBYILcu1K9SpiobtelCZX5_BHQrOJCCoaXtJCGX35eeFnQSAVggApvPGQYz3DLYRbetDpT0-31okQ5uzWRwzrff00yMD7oCWCD4d3HGgi-70QBlGoiU5nggSPzpSI5GkxXdsOyG4ArVLgNYIOQbLhdNqN_8kCZzqVswmMeQ6MtpvttlT16uBgWMKdFyBFgg_hMVI7VctilrrgdQPGCdIEL4VgkVVaEMEvKcIY_xJKUFWCAtv66ml2lD15WYUUzAS6gJYj1DALcrbw9xjFFrZkhUuG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmmAQICWCtlNjVnMnVDNmJCMEREZGZNRzhTYlZ2TDFNSWxSNENxcGRoUWE4YmZQUDNVAyYgASFYILQicKMUp8767SCHDrTO6yWjmAm-WIjudd3pRo_zI7myIlggPBprbay4iRPtNiVtbVob_u3AQxpRmqWQSup7zPyNuLlvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZYQBCVJ3YkZ1ETAuhULd1ZGTv6ONhH_NsP61FIfpe69uLWEBThcUiJq7y_KRMms9KVi7pYcU3WhiNlOUC6hSYrB_1qbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGG2BhYZaRmcmFuZG9tWBiq53HDBUk9X9igBaZDmBelpFQndR2-nl9oZGlnZXN0SUQAbGVsZW1lbnRWYWx1ZW0ke2ZhbWlseU5hbWV9cWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1l2BhYY6RmcmFuZG9tWBgvL1T9pXgeuDdhIpe9VL0dEFL8IXB5rkJoZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZWwke2dpdmVuTmFtZX1xZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWGOkZnJhbmRvbVgYMuPQgcDhX9FgtaLBg5aC2SmZpPPsyUYlaGRpZ2VzdElEAmxlbGVtZW50VmFsdWVsJHtiaXJ0aERhdGV9cWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGXYGFhepGZyYW5kb21YGG9QaSwv6jAPrlLBDqMcpymi-NiA9MEChGhkaWdlc3RJRANsZWxlbWVudFZhbHVlYklOcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWG2kZnJhbmRvbVgYKA4VkRJdH22UPLypb9bl72lXGuja-E2xaGRpZ2VzdElEBGxlbGVtZW50VmFsdWVxJHtkb2N1bWVudE51bWJlcn1xZWxlbWVudElkZW50aWZpZXJvZG9jdW1lbnRfbnVtYmVy2BhYYKRmcmFuZG9tWBhb4Thi6agJuh0LXOhY3pRuffpIZgeZq9xoZGlnZXN0SUQFbGVsZW1lbnRWYWx1ZWske3BvcnRyYWl0fXFlbGVtZW50SWRlbnRpZmllcmhwb3J0cmFpdA"
            )
        }
        assertEquals(ERROR_CODE_INVALID_DS_CERT_EKU, exception.errorCode)
    }

    @Test
    fun `should reject an mDL whose DS certificate lacks the mDL EKU`() {
        val credential = javaClass.classLoader
            .getResourceAsStream("mso_mdoc/mdl-missing-ds-eku.b64url")!!
            .bufferedReader()
            .use { it.readText().trim() }

        // Validation runs first: the fixture's disclosed claims omit mandatory elements.
        val validation = MsoMdocVerifiableCredential(optionsAt(MISSING_EKU_FIXTURE_NOW)).validate(credential)
        assertEquals(ERROR_CODE_INVALID_MDL_ELEMENT, validation.validationErrorCode)

        val exception = assertThrows(ValidationException::class.java) {
            verifierAt(MISSING_EKU_FIXTURE_NOW).verify(credential)
        }
        // The Certify DS certificate lacks the critical mDL EKU.
        assertEquals(ERROR_CODE_INVALID_DS_CERT_EKU, exception.errorCode)
    }

    @Test
    fun `should fail when DS certificate has no KeyUsage extension but EKU is present`() {
        val credential = MdlEdgeCaseTestDataGenerator.create(includeKeyUsage = false)

        val exception = assertThrows(ValidationException::class.java) {
            MsoMdocVerifier().verify(credential)
        }

        assertEquals(ERROR_CODE_INVALID_DS_CERT_KEY_USAGE, exception.errorCode)
    }

    @Test
    fun `should throw ERR_INVALID_ISSUING_COUNTRY when claim country mismatches DS C`() {
        val credential = MdlEdgeCaseTestDataGenerator.create(
            records = MdlEdgeCaseTestDataGenerator.recordsWith("issuing_country", UnicodeString("SA")),
        )
        val exception = assertThrows(ValidationException::class.java) {
            MsoMdocVerifier().verify(credential)
        }
        assertEquals(ERROR_CODE_INVALID_ISSUING_COUNTRY, exception.errorCode)
    }

    @Test
    fun `should throw ERR_INVALID_ISSUING_JURISDICTION when claim state mismatches DS ST`() {
        val credential = MdlEdgeCaseTestDataGenerator.create(
            records = MdlEdgeCaseTestDataGenerator.recordsWith("issuing_jurisdiction", UnicodeString("MH")),
        )
        val exception = assertThrows(ValidationException::class.java) {
            MsoMdocVerifier().verify(credential)
        }
        assertEquals(ERROR_CODE_INVALID_ISSUING_JURISDICTION, exception.errorCode)
    }

    private val factory = MdlEdgeCaseTestDataGenerator

    private fun allMandatoryExcept(identifier: String): Set<String> =
        factory.mandatoryRecords().map { it.first }.toSet() - identifier

    private fun assertVerifyFails(code: String, verifier: MsoMdocVerifier, credential: String) {
        val exception = assertThrows(ValidationException::class.java) { verifier.verify(credential) }
        assertEquals(code, exception.errorCode)
    }

    @org.junit.jupiter.api.Nested
    inner class `DS certificate KeyUsage and EKU` {
        @Test
        fun `should pass with a conformant DS certificate`() {
            assertTrue(MsoMdocVerifier().verify(factory.create(certificate = factory.generateCertificate())))
        }

        @Test
        fun `should fail when KeyUsage is present without digitalSignature`() {
            val certificate = factory.generateCertificate(keyUsage = KeyUsage.keyCertSign)
            assertVerifyFails(
                ERROR_CODE_INVALID_DS_CERT_KEY_USAGE,
                MsoMdocVerifier(),
                factory.create(certificate = certificate),
            )
        }

        @Test
        fun `should fail when KeyUsage is not critical`() {
            val certificate = factory.generateCertificate(keyUsageCritical = false)
            assertVerifyFails(
                ERROR_CODE_INVALID_DS_CERT_KEY_USAGE,
                MsoMdocVerifier(),
                factory.create(certificate = certificate),
            )
        }

        @Test
        fun `should fail when EKU is not critical`() {
            val certificate = factory.generateCertificate(ekuCritical = false)
            assertVerifyFails(
                ERROR_CODE_INVALID_DS_CERT_EKU,
                MsoMdocVerifier(),
                factory.create(certificate = certificate),
            )
        }

        @Test
        fun `should fail when EKU holds another OID`() {
            val certificate = factory.generateCertificate(ekuOid = "1.3.6.1.5.5.7.3.4")
            assertVerifyFails(
                ERROR_CODE_INVALID_DS_CERT_EKU,
                MsoMdocVerifier(),
                factory.create(certificate = certificate),
            )
        }

        @Test
        fun `should fail when EKU is missing`() {
            val certificate = factory.generateCertificate(ekuOid = null)
            assertVerifyFails(
                ERROR_CODE_INVALID_DS_CERT_EKU,
                MsoMdocVerifier(),
                factory.create(certificate = certificate),
            )
        }

        @Test
        fun `should skip the profile check when strict profile is off`() {
            val certificate = factory.generateCertificate(keyUsage = null, ekuOid = null)
            val credential = factory.create(certificate = certificate)
            assertTrue(MsoMdocVerifier(MsoMdocVerificationOptions(strictMdlProfile = false)).verify(credential))
        }
    }

    @org.junit.jupiter.api.Nested
    inner class `issuing_country vs DS certificate C` {
        @Test
        fun `should pass when issuing_country is not disclosed`() {
            // Selectively disclosed (still digested in the MSO): a hidden issuing_country must not fail verification.
            val credential = factory.create(discloseOnly = allMandatoryExcept("issuing_country"))
            assertTrue(MsoMdocVerifier().verify(credential))
        }

        @Test
        fun `should pass when issuing_country matches`() {
            assertTrue(MsoMdocVerifier().verify(readClasspathFile("mso_mdoc/mdl-valid.b64url").trim()))
        }

        @Test
        fun `should fail when the DS certificate has no C`() {
            val certificate = factory.generateCertificate(subject = "ST=KA,O=vc-verifier test")
            assertVerifyFails(
                ERROR_CODE_INVALID_ISSUING_COUNTRY,
                MsoMdocVerifier(),
                factory.create(certificate = certificate),
            )
        }

        @Test
        fun `should fail when a disclosed issuing_country is empty`() {
            val credential = factory.create(records = factory.recordsWith("issuing_country", UnicodeString("")))
            assertVerifyFails(ERROR_CODE_INVALID_ISSUING_COUNTRY, MsoMdocVerifier(), credential)
        }

        @Test
        fun `should ignore issuing_country disclosed only in another namespace`() {
            val credential = factory.create(
                discloseOnly = allMandatoryExcept("issuing_country"),
                extraNamespaces = mapOf("org.example.ns" to listOf("issuing_country" to UnicodeString("XX"))),
            )
            assertTrue(MsoMdocVerifier().verify(credential))
        }
    }

    @org.junit.jupiter.api.Nested
    inner class `issuing_jurisdiction vs DS certificate ST` {
        @Test
        fun `should pass when issuing_jurisdiction matches`() {
            val credential = factory.create(records = factory.recordsWith("issuing_jurisdiction", UnicodeString("KA")))
            assertTrue(MsoMdocVerifier().verify(credential))
        }

        @Test
        fun `should skip when the DS certificate has no ST`() {
            val certificate = factory.generateCertificate(subject = "C=IN,O=vc-verifier test")
            val credential = factory.create(
                certificate = certificate,
                records = factory.recordsWith("issuing_jurisdiction", UnicodeString("XX")),
            )
            assertTrue(MsoMdocVerifier().verify(credential))
        }

        @Test
        fun `should skip when issuing_jurisdiction is absent`() {
            assertTrue(MsoMdocVerifier().verify(factory.create()))
        }

        @Test
        fun `should compare the raw ST value, not the RFC 4514 escaped form`() {
            val certificate = factory.generateCertificate(subject = "C=IN,ST=Jammu\\, Kashmir,O=vc-verifier test")
            val credential = factory.create(
                certificate = certificate,
                records = factory.recordsWith("issuing_jurisdiction", UnicodeString("Jammu, Kashmir")),
            )
            assertTrue(MsoMdocVerifier().verify(credential))
        }

        @Test
        fun `should fail with a certificate error when the subject is unreadable`() {
            val principal = io.mockk.mockk<javax.security.auth.x500.X500Principal>()
            every { principal.encoded } returns byteArrayOf(0x01, 0x02)
            val certificate = io.mockk.mockk<java.security.cert.X509Certificate>()
            every { certificate.subjectX500Principal } returns principal
            val exception = assertThrows(ValidationException::class.java) {
                MdlVerifier.verify(emptyList(), CborMap(), certificate, MsoMdocVerificationOptions(strictMdlProfile = false))
            }
            assertEquals(ERROR_CODE_INVALID_DS_CERT_SUBJECT, exception.errorCode)
        }
    }
}
