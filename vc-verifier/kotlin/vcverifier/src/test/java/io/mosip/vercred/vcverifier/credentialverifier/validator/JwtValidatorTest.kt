package io.mosip.vercred.vcverifier.credentialverifier.validator

import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.utils.Util
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.Base64

class JwtValidatorTest {

    private val validator = JwtValidator()

    @BeforeEach
    fun setup() {
        mockkObject(Util)
        every { Util.verifyJwt(any(), any(), any()) } returns true
    }

    private fun loadSampleJwt(fileName: String): String {
        val file = ResourceUtils.getFile("classpath:jwt_vc/$fileName")
        return String(Files.readAllBytes(file.toPath())).trim()
    }

    private fun modifyJwtPayload(jwt: String, modify: (JSONObject) -> Unit): String {
        val parts = jwt.split(".")
        val payloadJson = JSONObject(String(Base64.getUrlDecoder().decode(parts[1])))
        modify(payloadJson)
        val modifiedPayload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.toString().toByteArray())
        return "${parts[0]}.$modifiedPayload.${parts[2]}"
    }

    @Test
    fun `should validate a valid JWT VC successfully`() {
        val vc = loadSampleJwt("validJwt.txt")
        val status = validator.validate(vc)

        assertEquals("", status.validationMessage)
        assertEquals("", status.validationErrorCode)
    }

    @Test
    fun `should fail for algorithm none`() {
        val header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".toByteArray())
        val payload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"iss\":\"test\"}".toByteArray())
        val noneVc = "$header.$payload." 
        val status = validator.validate(noneVc)
        
        assertEquals("INVALID_ALGORITHM", status.validationErrorCode)
        assertEquals("JWT algorithm 'none' is not allowed", status.validationMessage)
    }

    @Test
    fun `should fail if iss claim is missing`() {
        val vc = modifyJwtPayload(loadSampleJwt("validJwt.txt")) {
            it.remove("iss") 
        }
        val status = validator.validate(vc)

        assertEquals("INVALID_VC_FORMAT", status.validationErrorCode)
    }

    @Test
    fun `should fail for expired exp`() {
        val vc = modifyJwtPayload(loadSampleJwt("validJwt.txt")) {
            it.put("exp", (System.currentTimeMillis() / 1000) - 10000) 
        }
        val status = validator.validate(vc)
        assertEquals("ERROR_CODE_VC_EXPIRED", status.validationErrorCode)
    }

    @Test
    fun `should fail for future nbf`() {
        val vc = modifyJwtPayload(loadSampleJwt("validJwt.txt")) {
            it.put("nbf", (System.currentTimeMillis() / 1000) + 10000) 
        }
        val status = validator.validate(vc)

        assertEquals("ERROR_CODE_VC_NOT_YET_VALID", status.validationErrorCode)
    }

    @Test
    fun `should fail if vc claim is missing`() {
        val vc = modifyJwtPayload(loadSampleJwt("validJwt.txt")) {
            it.remove("vc") 
        }
        val status = validator.validate(vc)

        assertEquals("INVALID_VC_FORMAT", status.validationErrorCode)
    }

    @Test
    fun `should fail if sub does not match credentialSubject id`() {
        val vc = modifyJwtPayload(loadSampleJwt("validJwt.txt")) { 
            it.put("sub", "mismatched-id")
            // Ensuring credentialSubject.id is different from sub
            val vcMap = it.getJSONObject("vc")
            val subject = vcMap.getJSONObject("credentialSubject")
            subject.put("id", "actual-id")
        }
        val status = validator.validate(vc)
        assertEquals("INVALID_VC_FORMAT", status.validationErrorCode)
        assertEquals("Claim 'sub' must match 'credentialSubject.id'", status.validationMessage)
    }

    @Test
    fun `should fail if jti does not match vc id`() {
        val vc = modifyJwtPayload(loadSampleJwt("validJwt.txt")) { 
            it.put("jti", "urn:uuid:mismatched-jti")
            val vcMap = it.getJSONObject("vc")
            vcMap.put("id", "urn:uuid:actual-vc-id")
        }
        val status = validator.validate(vc)
        assertEquals("INVALID_VC_FORMAT", status.validationErrorCode)
        assertEquals("Claim 'jti' must match 'vc.id'", status.validationMessage)
    }
}
