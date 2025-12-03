package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mockk.MockKAnnotations
import io.mockk.every
import io.mockk.junit5.MockKExtension
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import io.mosip.vercred.vcverifier.credentialverifier.types.LdpVerifiableCredential
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
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
    private lateinit var checker: LdpStatusChecker

    @BeforeEach
    fun setup() {
        MockKAnnotations.init(this)
        mockkConstructor(LdpVerifiableCredential::class)
        every { anyConstructed<LdpVerifiableCredential>().verify(any()) } returns true
        checker = LdpStatusChecker()
    }

    @AfterEach
    fun teardown() {
        unmockkAll()
    }

    private fun readFile(path: String): String {
        val file = ResourceUtils.getFile(path)
        return String(Files.readAllBytes(file.toPath()))
    }

    private fun prepareVC(
        vcPath: String = "classpath:ldp_vc/vcUnrevoked-https.json",
        statusListJson: String
    ): Pair<String, MockWebServer> {
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

        assertEquals(1, results.size)
        assertTrue(results["revocation"]?.isValid == true)
        assertNotNull(results["revocation"])

        server.shutdown()
    }

    @Test
    fun `should return status != 0 when VC is revoked`() {
        val vcJson = readFile("classpath:ldp_vc/vcRevoked-https.json")
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")

        val (replacedVC, server) = prepareVCFromRaw(vcJson, statusListJson)
        val results = checker.getStatuses(replacedVC)

        assertEquals(1, results.size)
        assertTrue(results["revocation"]?.isValid == false)
        assertNotNull(results["revocation"])

        server.shutdown()
    }

    @Test
    fun `should throw error when credentialStatus is missing`() {
        val vcJson = readFile("classpath:ldp_vc/PS256SignedMosipVC.json")
        val result = checker.getStatuses(
            vcJson,
            listOf("suspension")
        )

        assertTrue(result.isEmpty())
    }

    @Test
    fun `should return empty map when require purpose is not available in credential`() {
        val vcJson = readFile("classpath:ldp_vc/vcRevoked-https.json")
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")

        val (replacedVC, server) = prepareVCFromRaw(vcJson, statusListJson)
        val result = checker.getStatuses(
            replacedVC,
            listOf("suspension")
        )

        assertTrue(result.isEmpty())
        server.shutdown()
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

        assertEquals(1, results.size)
        val result = results.entries.first()
        assertFalse(result.value.isValid)
        assertTrue(result.value.error is StatusCheckException)
        assertTrue(result.value.error?.message?.contains("Retrieval of the status list failed") == true)
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

        val result = checker.getStatuses(replacedVC).entries.first()

        assertFalse(result.value.isValid)
        assertEquals(StatusCheckErrorCode.RANGE_ERROR, result.value.error?.errorCode)
        assertEquals("Bit position 999999 out of range", result.value.error?.message)
        server.shutdown()
    }

    @Test
    fun `should return error when encodedList is missing`() {
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace("encodedList", "encList")
        val (replacedVC, server) = prepareVC(
            statusListJson = statusListJson
        )

        val result = checker.getStatuses(replacedVC).entries.first()

        assertFalse(result.value.isValid)
        assertEquals(StatusCheckErrorCode.ENCODED_LIST_MISSING, result.value.error?.errorCode)
        assertEquals("Missing 'encodedList'", result.value.error?.message)
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
            statusListJson = statusListJson
        )

        val result = checker.getStatuses(replacedVC).entries.first()
        assertFalse(result.value.isValid)
        assertEquals(StatusCheckErrorCode.BASE64_DECODE_FAILED, result.value.error?.errorCode)

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
            statusListJson = statusListJson
        )

        val result = checker.getStatuses(replacedVC).entries.first()
        assertFalse(result.value.isValid)
        assertEquals(StatusCheckErrorCode.GZIP_DECOMPRESS_FAILED, result.value.error?.errorCode)

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
            statusListJson = statusListJson
        )

        val result = checker.getStatuses(replacedVC).entries.first()
        assertFalse(result.value.isValid)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, result.value.error?.errorCode)
        assertEquals(
            "Status list VC purpose mismatch. Expected 'revocation', found 'suspension'",
            result.value.error?.message
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

        val result = checker.getStatuses(replacedVC).entries.first()
        assertFalse(result.value.isValid)
        assertEquals(StatusCheckErrorCode.INVALID_PURPOSE, result.value.error?.errorCode)
        assertEquals("statusPurpose Invalid", result.value.error?.message)
        server.shutdown()
    }

    @Test
    fun `should return error when statusSize is zero or negative`() {
        val statusListJsonNegative = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace("\"encodedList\"", "\"statusSize\": -2, \"encodedList\"")
        val statusListJsonZero = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace("\"encodedList\"", "\"statusSize\": 0, \"encodedList\"")
        val (replacedVC, server) = prepareVC(statusListJson = statusListJsonNegative)
        val (replacedVCZero, _) = prepareVC(
            statusListJson = statusListJsonZero
        )

        val resultNeg = checker.getStatuses(replacedVC).entries.first()

        assertFalse(resultNeg.value.isValid)
        assertEquals(
            StatusCheckErrorCode.STATUS_VERIFICATION_ERROR,
            resultNeg.value.error?.errorCode
        )

        val resultZero = checker.getStatuses(replacedVCZero).entries.first()

        assertFalse(resultZero.value.isValid)
        assertEquals(
            StatusCheckErrorCode.STATUS_VERIFICATION_ERROR,
            resultZero.value.error?.errorCode
        )

        server.shutdown()
    }

    @Test
    fun `should return error when statusMessage missing for statusSize greater than one`() {
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace("\"encodedList\"", "\"statusSize\": 2, \"encodedList\"")

        val (replacedVC, server) = prepareVC(
            statusListJson = statusListJson
        )

        val result = checker.getStatuses(replacedVC).entries.first()

        assertFalse(result.value.isValid)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, result.value.error?.errorCode)
        assertEquals("Missing 'statusMessage' for statusSize=2", result.value.error?.message)

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

        val result = checker.getStatuses(replacedVC).entries.first()

        assertTrue(result.value.isValid)

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

        val result = checker.getStatuses(replacedVC).entries.first()

        assertFalse(result.value.isValid)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, result.value.error?.errorCode)
        assertEquals(
            "statusMessage count mismatch. Expected 4 entries for statusSize=2, found 3",
            result.value.error?.message
        )

        server.shutdown()
    }


    @Test
    fun `should return error when credentialSubject type is missing or invalid`() {
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
            .replace(Regex(""""type":\s*".*?","""), "") // remove type from credentialSubject
        val (replacedVC, server) = prepareVC(
            statusListJson = statusListJson
        )

        val result = checker.getStatuses(replacedVC).entries.first()
        assertFalse(result.value.isValid)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, result.value.error?.errorCode)
        assertEquals("Missing 'type' in status list credential", result.value.error?.message)
        server.shutdown()
    }

    @Test
    fun `should return error when statusListIndex missing in credentialStatus`() {
        val vcJson = readFile("classpath:ldp_vc/vcUnrevoked-https.json")
            .replace(Regex(""""statusListIndex":\s*".*?",?"""), "")
        val statusListJson = readFile("classpath:ldp_vc/status-list-vc.json")
        val (replacedVC, server) = prepareVCFromRaw(vcJson, statusListJson)

        val result = checker.getStatuses(replacedVC).entries.first()
        assertFalse(result.value.isValid)
        assertEquals(StatusCheckErrorCode.INVALID_INDEX, result.value.error?.errorCode)
        assertEquals("Invalid or missing 'statusListIndex'", result.value.error?.message)
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
            statusListJson = statusListJson
        )

        val result = checker.getStatuses(replacedVC).entries.first()

        assertFalse(result.value.isValid)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, result.value.error?.errorCode)
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
            statusListJson = statusListJson
        )

        val result = checker.getStatuses(replacedVC).entries.first()

        assertFalse(result.value.isValid)
        assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, result.value.error?.errorCode)

        server.shutdown()
    }


}
