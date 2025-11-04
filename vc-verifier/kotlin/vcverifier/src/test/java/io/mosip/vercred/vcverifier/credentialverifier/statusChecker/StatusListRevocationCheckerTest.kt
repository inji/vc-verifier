package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mockk.MockKAnnotations
import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.junit5.MockKExtension
import io.mockk.unmockkAll
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifierFactory
import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.Base64
import java.util.regex.Matcher

@ExtendWith(MockKExtension::class)
class StatusListRevocationCheckerTest {

    @MockK
    lateinit var mockVerifierFactory: CredentialVerifierFactory

    @MockK
    lateinit var mockVerifier: VerifiableCredential

    private lateinit var checker: LdpStatusChecker

    @BeforeEach
    fun setup() {
        MockKAnnotations.init(this)
        every { mockVerifierFactory.get(CredentialFormat.LDP_VC) } returns mockVerifier
        every { mockVerifier.verify(any()) } returns true
        checker = LdpStatusChecker(mockVerifierFactory)
    }

    @AfterEach
    fun teardown() {
        unmockkAll()
    }

    private fun readFile(path: String): String {
        val file = ResourceUtils.getFile(path)
        return String(Files.readAllBytes(file.toPath()))
    }

    private fun prepareVC(vcPath: String, statusListJson: String): Pair<String, MockWebServer> {
        val vcJson = readFile(vcPath)
        val server = MockWebServer().apply {
            enqueue(MockResponse().setResponseCode(200).setBody(statusListJson))
            start()
        }
        val mockUrl = server.url("/revocation-list").toString()
        val replacedVC = vcJson.replace(
            Regex(""""statusListCredential":\s*".*?""""),
            """"statusListCredential": "$mockUrl""""
        )
        return replacedVC to server
    }

    private fun prepareVCFromRaw(
        vcJson: String,
        statusListJson: String
    ): Pair<String, MockWebServer> {
        val server = MockWebServer().apply {
            enqueue(MockResponse().setResponseCode(200).setBody(statusListJson))
            start()
        }
        val mockUrl = server.url("/revocation-list").toString()
        val replacedVC = vcJson.replace(
            Regex(""""statusListCredential":\s*".*?""""),
            """"statusListCredential": "$mockUrl""""
        )
        return replacedVC to server
    }

    @Test
    fun `should return status == 0 when VC is not revoked`() {
        val vcJson = readFile("classpath:ldp_vc/vcUnrevoked-https.json")
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")

        val (replacedVC, server) = prepareVCFromRaw(vcJson, statusListJson)
        val results = checker.getStatuses(replacedVC, listOf("revocation"))

        assertNotNull(results)
        assertEquals(1, results!!.size)
        assertEquals(0, results.first().status)
        assertTrue(results.first().valid)

        server.shutdown()
    }

    @Test
    fun `should return status != 0 when VC is revoked`() {
        val vcJson = readFile("classpath:ldp_vc/vcRevoked-https.json")
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")

        val (replacedVC, server) = prepareVCFromRaw(vcJson, statusListJson)
        val results = checker.getStatuses(replacedVC)

        assertNotNull(results)
        assertEquals(1, results!!.size)
        assertNotEquals(0, results.first().status)
        assertFalse(results.first().valid)

        server.shutdown()
    }

    @Test
    fun `should return null when credentialStatus is missing`() {
        val vcJson = readFile("classpath:ldp_vc/PS256SignedMosipVC.json")
        val results = checker.getStatuses(vcJson)
        assertNull(results)
    }

    @Test
    fun `should return status with error on invalid statusListCredential URL`() {
        val vcJson = readFile("classpath:ldp_vc/vcRevoked-https.json")
        val replacedVC = vcJson.replace(
            Regex(""""statusListCredential"\s*:\s*".*?""""),
            """"statusListCredential": "http://localhost:9999/invalid-url""""
        )

        // Simulate network error by not starting the server
        val results = checker.getStatuses(replacedVC)

        assertNotNull(results)
        assertEquals(1, results!!.size)
        val result = results.first()
        assertEquals(-1, result.status)
        assertFalse(result.valid)
        assertTrue(result.error is StatusCheckException)
        assertTrue(result.error?.message?.contains("Retrieval of the status list failed") == true)
    }

    @Test
    fun `should return RANGE_ERROR when statusListIndex exceeds bitstring length`() {
        val vcJson = readFile("classpath:ldp_vc/vcUnrevoked-https.json")
            .replace(
                Regex(""""statusListIndex"\s*:\s*"\d+""""),
                """"statusListIndex": "999999""""
            )
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
        val (replacedVC, server) = prepareVCFromRaw(vcJson, statusListJson)

        val result = checker.getStatuses(replacedVC)!!.first()

        assertFalse(result.valid)
        assertEquals(-1, result.status)
        assertEquals(StatusCheckErrorCode.RANGE_ERROR, result.error?.errorCode)
        assertEquals("Bit position 999999 out of range", result.error?.message)
        server.shutdown()
    }

    @Test
    fun `should return error when encodedList is missing`() {
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace("encodedList", "encList")
        val (replacedVC, server) = prepareVC(
            "classpath:ldp_vc/vcUnrevoked-https.json",
            statusListJson
        )

        val result = checker.getStatuses(replacedVC)!!.first()

        assertFalse(result.valid)
        assertEquals(-1, result.status)
        assertEquals(StatusCheckErrorCode.ENCODED_LIST_MISSING, result.error?.errorCode)
        assertEquals("Missing 'encodedList'", result.error?.message)
        server.shutdown()
    }

    @Test
    fun `should return error on invalid base64 in encodedList`() {
        val corruptedBase64 = "uSGVsbG8@#$%^&*"
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace(
                Regex(""""encodedList":\s*".*?""""),
                Matcher.quoteReplacement(""""encodedList": "$corruptedBase64"""")
            )
        val (replacedVC, server) = prepareVC(
            "classpath:ldp_vc/vcUnrevoked-https.json",
            statusListJson
        )

        val result = checker.getStatuses(replacedVC)!!.first()
        assertFalse(result.valid)
        assertEquals(-1, result.status)
        assertEquals(StatusCheckErrorCode.BASE64_DECODE_FAILED, result.error?.errorCode)

        server.shutdown()
    }


    @Test
    fun `should return error on invalid GZIP data`() {
        val badData = Base64.getUrlEncoder().encodeToString("notGzipData".toByteArray())
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace(
                Regex(""""encodedList":\s*".*?""""),
                """"encodedList": "u$badData""""
            )
        val (replacedVC, server) = prepareVC(
            "classpath:ldp_vc/vcUnrevoked-https.json",
            statusListJson
        )

        val result = checker.getStatuses(replacedVC)!!.first()
        assertFalse(result.valid)
        assertEquals(-1, result.status)
        assertEquals(StatusCheckErrorCode.GZIP_DECOMPRESS_FAILED, result.error?.errorCode)

        server.shutdown()
    }

    @Test
    fun `should return error when statusPurpose mismatches in statusList VC`() {
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace(
                Regex(""""statusPurpose":\s*".*?""""),
                """"statusPurpose": "suspension""""
            )
        val (replacedVC, server) = prepareVC(
            "classpath:ldp_vc/vcUnrevoked-https.json",
            statusListJson
        )

        val result = checker.getStatuses(replacedVC)!!.first()
        assertFalse(result.valid)
        assertEquals(-1, result.status)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, result.error?.errorCode)
        assertEquals(
            "Status list VC purpose mismatch. Expected 'revocation', found 'suspension'",
            result.error?.message
        )
        server.shutdown()
    }

    @Test
    fun `should return error if statusPurpose is missing in VC credentialStatus entry`() {
        val vcJson = readFile("classpath:ldp_vc/vcUnrevoked-https.json")
            .replace(
                Regex("""(,\s*"statusPurpose"\s*:\s*".*?")|("statusPurpose"\s*:\s*".*?",)"""),
                ""
            )

        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
        val (replacedVC, server) = prepareVCFromRaw(vcJson, statusListJson)

        val result = checker.getStatuses(replacedVC)!!.first()
        assertFalse(result.valid)
        assertEquals(-1, result.status)
        assertEquals(StatusCheckErrorCode.INVALID_PURPOSE, result.error?.errorCode)
        assertEquals("statusPurpose Invalid", result.error?.message)
        server.shutdown()
    }

    @Test
    fun `should return error when statusSize is zero or negative`() {
        val statusListJsonNegative = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace("\"encodedList\"", "\"statusSize\": -2, \"encodedList\"")
        val statusListJsonZero = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace("\"encodedList\"", "\"statusSize\": 0, \"encodedList\"")
        val (replacedVC, server) = prepareVC(
            "classpath:ldp_vc/vcUnrevoked-https.json",
            statusListJsonNegative
        )
        val (replacedVCZero, serverZero) = prepareVC(
            "classpath:ldp_vc/vcUnrevoked-https.json",
            statusListJsonZero
        )

        val resultNeg = checker.getStatuses(replacedVC)!!.first()

        assertFalse(resultNeg.valid)
        assertEquals(-1, resultNeg.status)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, resultNeg.error?.errorCode)

        val resultZero = checker.getStatuses(replacedVCZero)!!.first()

        assertFalse(resultZero.valid)
        assertEquals(-1, resultZero.status)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, resultZero.error?.errorCode)

        server.shutdown()
    }

    @Test
    fun `should return error when statusMessage missing for statusSize greater than one`() {
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace("\"encodedList\"", "\"statusSize\": 2, \"encodedList\"")

        val (replacedVC, server) = prepareVC(
            "classpath:ldp_vc/vcUnrevoked-https.json",
            statusListJson
        )

        val result = checker.getStatuses(replacedVC)!!.first()

        assertFalse(result.valid)
        assertEquals(-1, result.status)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, result.error?.errorCode)
        assertEquals("Missing 'statusMessage' for statusSize=2", result.error?.message)

        server.shutdown()
    }

    @Test
    fun `should pass when statusMessage count matches statusSize`() {
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace("\"encodedList\"", "\"statusSize\": 2, \"encodedList\"") // Add mismatched size

        val vcJsonOriginal = readFile("classpath:ldp_vc/vcUnrevoked-https.json")

        // Add statusMessage just before closing of credentialStatus map
        val vcJsonModified = vcJsonOriginal.replace(
            Regex(""""statusListIndex"\s*:\s*".*?"\s*"""),
            """
        "statusListIndex": "2",
        "statusMessage": {
          "0": "active",
          "1": "revoked",
          "2": "suspended",
          "3": "deactivated"
        }
      """.trimIndent()
        )

        val (replacedVC, server) = prepareVCFromRaw(vcJsonModified, statusListJson)

        val result = checker.getStatuses(replacedVC)!!.first()

        assertTrue(result.valid)
        assertEquals(0, result.status)

        server.shutdown()
    }


    @Test
    fun `should return error when statusMessage count mismatches statusSize`() {
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace("\"encodedList\"", "\"statusSize\": 2, \"encodedList\"") // Add mismatched size

        val vcJsonOriginal = readFile("classpath:ldp_vc/vcUnrevoked-https.json")

        // Add statusMessage just before closing of credentialStatus map
        val vcJsonModified = vcJsonOriginal.replace(
            Regex(""""statusListIndex"\s*:\s*".*?"\s*"""),
            """
        "statusListIndex": "2",
        "statusMessage": {
          "0": "active",
          "1": "revoked",
          "2": "suspended"
        }""".trimIndent()
        )

        val (replacedVC, server) = prepareVCFromRaw(vcJsonModified, statusListJson)

        val result = checker.getStatuses(replacedVC)!!.first()

        assertFalse(result.valid)
        assertEquals(-1, result.status)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, result.error?.errorCode)
        assertEquals(
            "statusMessage count mismatch. Expected 4 entries for statusSize=2, found 3",
            result.error?.message
        )

        server.shutdown()
    }


    @Test
    fun `should return error when credentialSubject type is missing or invalid`() {
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace(Regex(""""type":\s*".*?","""), "") // remove type from credentialSubject
        val (replacedVC, server) = prepareVC(
            "classpath:ldp_vc/vcUnrevoked-https.json",
            statusListJson
        )

        val result = checker.getStatuses(replacedVC)!!.first()
        assertFalse(result.valid)
        assertEquals(-1, result.status)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, result.error?.errorCode)
        assertEquals("Missing 'type' in status list credential", result.error?.message)
        server.shutdown()
    }

    @Test
    fun `should return error when statusListIndex missing in credentialStatus`() {
        val vcJson = readFile("classpath:ldp_vc/vcUnrevoked-https.json")
            .replace(Regex(""""statusListIndex":\s*".*?",?"""), "")
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
        val (replacedVC, server) = prepareVCFromRaw(vcJson, statusListJson)

        val result = checker.getStatuses(replacedVC)!!.first()
        assertFalse(result.valid)
        assertEquals(-1, result.status)
        assertEquals(StatusCheckErrorCode.INVALID_INDEX, result.error?.errorCode)
        assertEquals("Invalid or missing 'statusListIndex'", result.error?.message)
        server.shutdown()
    }

    @Test
    fun `should return error when validFrom is in the future`() {
        val futureValidFrom = java.time.Instant.now().plusSeconds(86400).toString() // 1 day later

        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace(
                Regex(""""credentialSubject":\s*\{"""),
                """"credentialSubject": {
                "validFrom": "$futureValidFrom","""
            )

        val (replacedVC, server) = prepareVC(
            "classpath:ldp_vc/vcUnrevoked-https.json",
            statusListJson
        )

        val result = checker.getStatuses(replacedVC)!!.first()

        assertFalse(result.valid)
        assertEquals(-1, result.status)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, result.error?.errorCode)
        server.shutdown()
    }

    @Test
    fun `should return error when validUntil is in the past`() {
        val pastValidUntil = java.time.Instant.now().minusSeconds(86400).toString() // 1 day earlier

        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace(
                Regex(""""credentialSubject":\s*\{"""),
                """"credentialSubject": {
                "validUntil": "$pastValidUntil","""
            )

        val (replacedVC, server) = prepareVC(
            "classpath:ldp_vc/vcUnrevoked-https.json",
            statusListJson
        )

        val result = checker.getStatuses(replacedVC)!!.first()

        assertFalse(result.valid)
        assertEquals(-1, result.status)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, result.error?.errorCode)

        server.shutdown()
    }


}
