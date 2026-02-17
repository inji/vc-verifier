package io.mosip.vercred.vcverifier.credentialverifier.validator

import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.Base64

class JwtValidatorTest {

    private val validator = JwtValidator()

    private fun loadSampleJwt(fileName: String): String {
        val file = ResourceUtils.getFile("classpath:jwt_vc/$fileName")
        return String(Files.readAllBytes(file.toPath())).trim()
    }

    private fun modifyJwtPayload(jwt: String, modify: (JSONObject) -> Unit): String {
        val parts = jwt.split(".")
        val payload = parts[1]

        val payloadJson = JSONObject(String(Base64.getUrlDecoder().decode(payload)))
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
    fun `should fail for invalid JWT format`() {
        val status = validator.validate("this.isnot.a.jwt.structure")
        
        assertEquals("Invalid characters or format in JWT", status.validationMessage)
        assertEquals("MALFORMED_INPUT", status.validationErrorCode)
    }

    @Test
    fun `should fail for expired exp`() {
        val vc = modifyJwtPayload(loadSampleJwt("validJwt.txt")) {
            it.put("exp", 1234567890) 
        }
        val status = validator.validate(vc)
        
        assertEquals("VC has expired", status.validationMessage)
        assertEquals("ERROR_CODE_VC_EXPIRED", status.validationErrorCode)
    }

    @Test
    fun `should fail for future nbf`() {
        val vc = modifyJwtPayload(loadSampleJwt("validJwt.txt")) {
            it.put("nbf", 9999999999) 
        }
        val status = validator.validate(vc)
        
        assertEquals("VC is not yet valid", status.validationMessage)
        assertEquals("ERROR_CODE_VC_NOT_YET_VALID", status.validationErrorCode)
    }

    @Test
    fun `should fail if vc claim is missing`() {
        val vc = modifyJwtPayload(loadSampleJwt("validJwt.txt")) {
            it.remove("vc") 
        }
        val status = validator.validate(vc)
        
        assertEquals("Missing 'vc' claim in payload", status.validationMessage)
        assertEquals("INVALID_VC_FORMAT", status.validationErrorCode)
    }
}
