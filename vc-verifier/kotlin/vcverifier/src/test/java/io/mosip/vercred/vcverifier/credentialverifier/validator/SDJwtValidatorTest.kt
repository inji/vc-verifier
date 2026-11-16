package io.mosip.vercred.vcverifier.credentialverifier.validator

import io.mockk.every
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mosip.vercred.vcverifier.signature.impl.ES256KSignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.Util
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.Base64

class SdJwtValidatorTest {

    @BeforeEach
    fun setup() {
        mockkObject(Util)
        every { Util.verifyJwt(
            any(),
          any(),
          any()
        ) } returns true
    }

    private val validator = SdJwtValidator()

    private fun validatePlainSdJwt(credential: String) =
        validator.validate(credential, validateKeyBindingJwt = false)

    private fun loadSampleSdJwt(fileName: String): String {
        val file = ResourceUtils.getFile("classpath:sd-jwt_vc/$fileName")
        return String(Files.readAllBytes(file.toPath()))
    }

    private fun modifySdJwtPayload(sdJwt: String, modify: (JSONObject) -> Unit): String {
        val parts = sdJwt.split("~")
        val jwtParts = parts[0].split(".")
        val header = jwtParts[0]
        val payload = jwtParts[1]
        val signature = jwtParts[2]

        val payloadJson = JSONObject(String(Base64.getUrlDecoder().decode(payload)))
        modify(payloadJson)

        val modifiedPayload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.toString().toByteArray())

        val newJwt = listOf(header, modifiedPayload, signature).joinToString(".")
        return listOf(newJwt).plus(parts.drop(1)).joinToString("~")
    }
    private fun modifyKbJwtHeader(jwt: String, modify: (JSONObject) -> Unit): String {
        val parts = jwt.split(".")
        val header = JSONObject(String(Base64.getUrlDecoder().decode(parts[0])))
        modify(header)
        val encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.toString().toByteArray())
        return listOf(encodedHeader, parts[1], parts[2]).joinToString(".")
    }

    fun modifyKbJwtPayload(kbJwt: String, modify: (JSONObject) -> Unit): String {
        val jwtParts = kbJwt.split(".")
        require(jwtParts.size == 3) { "Invalid JWT format" }

        val header = jwtParts[0]
        val payload = jwtParts[1]
        val signature = jwtParts[2]

        val payloadJson = JSONObject(String(Base64.getUrlDecoder().decode(payload)))
        modify(payloadJson)

        val modifiedPayload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.toString().toByteArray())

        return listOf(header, modifiedPayload, signature).joinToString(".")
    }

    private fun modifySdJwtHeader(sdJwt: String, modify: (JSONObject) -> Unit): String {
        val parts = sdJwt.split("~")
        val jwtParts = parts[0].split(".")
        val header = jwtParts[0]
        val payload = jwtParts[1]
        val signature = jwtParts[2]

        val headerJson = JSONObject(String(Base64.getUrlDecoder().decode(header)))
        modify(headerJson)

        val modifiedHeader = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(headerJson.toString().toByteArray())

        val newJwt = listOf(modifiedHeader, payload, signature).joinToString(".")
        return listOf(newJwt).plus(parts.drop(1)).joinToString("~")
    }

    private fun getDisclosureTamperedSdJWT(): String{
        val vc = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        val parts = vc.split("~").toMutableList()
        val tamperedDisclosure = "WyIzeGN5R1RuS1lsYV9VOUtGVEtEVWtRIiwiZmFybWVySUQiLCIxMjM0NTY3ODkiXQ"
        parts[parts.lastIndex - 1] = tamperedDisclosure
        return parts.joinToString("~")
    }

    @Test
    fun `should validate a valid SD-JWT VC successfully`() {
        var vc = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        var status = validator.validate(vc, validateKeyBindingJwt = false)
        assertEquals("", status.validationMessage)
        assertEquals("", status.validationErrorCode)
        vc = loadSampleSdJwt("sdJwtWithRootLevelSd2.txt")
        status = validator.validate(vc, validateKeyBindingJwt = false)
        assertEquals("", status.validationMessage)
        assertEquals("", status.validationErrorCode)
        vc = loadSampleSdJwt("sdJwtWithRootLevelSd.txt")
        status = validator.validate(vc, validateKeyBindingJwt = false)
        assertEquals("", status.validationMessage)
        assertEquals("", status.validationErrorCode)

    }

    @Test
    fun `should fail on empty string`() {
        val status = validator.validate("")
        assertEquals("Validation Error: Input VC JSON string is null or empty.",status.validationMessage)
        assertEquals("ERR_EMPTY_VC",status.validationErrorCode)
    }

    @Test
    fun `should fail on empty alg in header`() {
        val vc = modifySdJwtHeader(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.remove("alg")
        }
        val status = validator.validate(vc, validateKeyBindingJwt = false)
        assertEquals("Missing or invalid 'alg' in JWT header",status.validationMessage)
        assertEquals("ERR_INVALID_ALG",status.validationErrorCode)
    }

    @Test
    fun `should fail for invalid JWT format`() {
        val status = validatePlainSdJwt("invalid.ajbsdj.sdjbja.jwt.structure~")
        assertEquals("Validation Error: Invalid JWT format", status.validationMessage)
        assertEquals("ERR_INVALID_JWT_FORMAT",status.validationErrorCode)
    }

    @Test
    fun `should fail if vct is missing`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.remove("vct")
        }
        val status = validatePlainSdJwt(vc)
        assertEquals("Validation Error: Missing or empty 'vct' in JWT payload", status.validationMessage)
        assertEquals("ERR_MISSING_VCT",status.validationErrorCode)
    }

    @Test
    fun `should fail if vct is not valid`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.put("vct", "http:///invalid-vct-url")
        }
        val status = validatePlainSdJwt(vc)
        assertEquals("Validation Error: 'vct' must be a valid URI when it contains ':'", status.validationMessage)
        assertEquals("ERR_INVALID_VCT_URI",status.validationErrorCode)
    }

    @Test
    fun `should fail for invalid typ header`() {
        val vc = loadSampleSdJwt("sdJwt.txt")
        val parts = vc.split("~")
        val jwtParts = parts[0].split(".")
        val headerJson = JSONObject(String(Base64.getUrlDecoder().decode(jwtParts[0])))
        headerJson.put("typ", "unsupported-type")
        val newHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.toString().toByteArray())
        val newJwt = listOf(newHeader, jwtParts[1], jwtParts[2]).joinToString(".")
        val modified = listOf(newJwt).plus(parts.drop(1)).joinToString("~")
        val status = validatePlainSdJwt(modified)
        assertEquals("Unsupported or missing 'typ' in JWT header", status.validationMessage)
        assertEquals("ERR_INVALID_TYP",status.validationErrorCode)
    }

    @Test
    fun `should fail for future iat`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.put("iat", 9999999999)
        }
        val status = validatePlainSdJwt(vc)
        assertEquals("Validation Error: The current date time is before the issuanceDate", status.validationMessage)
        assertEquals("ERR_ISSUANCE_DATE_IS_FUTURE_DATE",status.validationErrorCode)
    }

    @Test
    fun `should fail for future nbf`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.put("nbf", 9999999999)
        }
        val status = validatePlainSdJwt(vc)
        assertEquals("Validation Error: The current date time is before the not before(nbf) claim Date", status.validationMessage)
        assertEquals("ERR_PROCESSING_DATE_IS_FUTURE_DATE",status.validationErrorCode)
    }

    @Test
    fun `should fail for expired exp`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.put("exp", 1234567890)
        }
        val status = validatePlainSdJwt(vc)
        assertEquals("VC is expired", status.validationMessage)
        assertEquals("ERR_VC_EXPIRED",status.validationErrorCode)
    }

    @Test
    fun `should fail for malformed disclosure`() {
        val base = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        val parts = base.split("~").toMutableList()

        parts[parts.lastIndex - 1] = "!!!not_base64"

        val modifiedVc = parts.joinToString("~")
        val status = validatePlainSdJwt(modifiedVc)
        assertEquals("Exception during Validation: Failed to parse disclosures.", status.validationMessage)
        assertEquals("ERR_INVALID_UNKNOWN",status.validationErrorCode)
    }

    @Test
    fun `should fail if _sd digest is not correct length for sha-256`() {
        val base = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        val parts = base.split("~").toMutableList()

        val jwtParts = parts[0].split(".").toMutableList()
        val payload = JSONObject(String(Base64.getUrlDecoder().decode(jwtParts[1])))
        payload.remove("_sd_alg")

        val shortDigest = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(ByteArray(16)) // 16 bytes
        val sdArray = payload.getJSONArray("_sd")
        sdArray.put(0, shortDigest)
        val newPayload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payload.toString().toByteArray())

        val newJwt = jwtParts[0] + "." + newPayload + "." + jwtParts[2]
        parts[0] = newJwt
        val modifiedVc = parts.joinToString("~")
        val status = validatePlainSdJwt(modifiedVc)
        assertEquals("Invalid digest length of digest: expected 32 bytes, got 16", status.validationMessage)
        assertEquals("ERR_INVALID_DIGEST",status.validationErrorCode)

    }

    @Test
    fun `should fail is _sd_alg is not supported`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.put("_sd_alg", "sha3-384")
        }
        val status = validatePlainSdJwt(vc)

        assertEquals("Unsupported _sd_alg: sha3-384. Allowed: [sha-256, sha-384, sha-512]", status.validationMessage)
        assertEquals("ERR_INVALID_SD_ALG",status.validationErrorCode)
    }

    @Test
    fun `should not fail if optional parameter iss is missing`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.remove("iss")
        }
        val status = validatePlainSdJwt(vc)

        assertEquals("", status.validationMessage)
        assertEquals("",status.validationErrorCode)
    }

    @Test
    fun `should fail if optional parameter iss is number`() {
        val iss = 12345
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.put("iss", iss)
        }
        val status = validatePlainSdJwt(vc)

        assertEquals("Invalid 'iss' claim: $iss", status.validationMessage)
        assertEquals("ERR_INVALID_ISS",status.validationErrorCode)
    }

    @Test
    fun `should fail if optional parameter aud is empty`() {
        val aud = "https:///iss"
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.put("aud", aud)
        }
        val status = validatePlainSdJwt(vc)

        assertEquals("Validation Error: Invalid URI: https:///iss", status.validationMessage)
        assertEquals("ERR_INVALID_AUD",status.validationErrorCode)
    }

    @Test
    fun `should fail if optional parameter nonce is empty`() {
        val nonce = "https:///nonce"
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.put("nonce", nonce)
        }
        val status = validatePlainSdJwt(vc)

        assertEquals("Validation Error: Invalid URI: https:///nonce", status.validationMessage)
        assertEquals("ERR_INVALID_NONCE",status.validationErrorCode)
    }

    @Test
    fun `should fail if cnf has both jwk and kid`() {
        val cnf = mapOf(
            "jwk" to mapOf("kty" to "RSA", "n" to "some-n", "e" to "AQAB"),
            "kid" to "some-kid"
        )
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.put("cnf", cnf)
        }
        val status = validator.validate(vc)

        assertEquals("Invalid 'cnf' object: must contain either 'jwk' or 'kid'", status.validationMessage)
        assertEquals("ERR_INVALID_CNF",status.validationErrorCode)
    }

    @Test
    fun `should fail for disclosure with reserved claim name`() {
        val base = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        val parts = base.split("~").toMutableList()

        val badDisclosure = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("[\"salt\",\"_bad\",\"value\"]".toByteArray())

        parts[parts.lastIndex - 1] = badDisclosure

        val modifiedVc = parts.joinToString("~")
        val status = validatePlainSdJwt(modifiedVc)

        assertEquals("Validation Error: Disclosure has invalid or reserved claim name (starts with underscore) at index 12", status.validationMessage)
        assertEquals("ERR_INVALID_DISCLOSURE_CLAIM_NAME" ,status.validationErrorCode)
    }

    @Test
    fun `should fail for malformed KB JWT`() {
        val vc = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt") + "header.payload"
        val status = validator.validate(vc)
        assertEquals("Validation Error: Invalid Key Binding JWT format", status.validationMessage)
        assertEquals("ERR_INVALID_KB_JWT_FORMAT",status.validationErrorCode)
    }

    @Test
    fun `should fail for missing aud in KB JWT`() {
        val validKbJwt = "ewogICJhbGciOiAiRVMyNTYiLAogICJ0eXAiOiAia2Irand0Igp9.eyJub25jZSI6ImFiYyIsImNuZiI6eyJraWQiOiJrZXkifX0.c2lnbmF0dXJl"
        val vc = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt") + validKbJwt
        val status = validator.validate(vc)
        assertEquals("Missing 'aud' in Key Binding JWT", status.validationMessage)
        assertEquals("ERR_MISSING_AUD",status.validationErrorCode)
    }

    @Test
    fun `should fail for tampered disclosure`() {
        val vc = getDisclosureTamperedSdJWT()
        val status = validatePlainSdJwt(vc)
        assertEquals("Digest value of all disclosures must be present in the '_sd' claim of payload", status.validationMessage)
        assertEquals("ERR_INVALID_DISCLOSURE",status.validationErrorCode)
    }

    @Test
    fun `should validate sd jwt with _sd in disclosures`() {
        val vc = loadSampleSdJwt("sdJwtWithClaimsInDisclosure.txt")
        val status = validatePlainSdJwt(vc)
        assertEquals("", status.validationMessage)
        assertEquals("",status.validationErrorCode)
    }

    @Test
    fun `should validate sd jwt with _sd in child object of payload`() {
        val vc = loadSampleSdJwt("sdJwtWithSDClaimsinChildObject.txt")
        val status = validatePlainSdJwt(vc)
        assertEquals("", status.validationMessage)
        assertEquals("",status.validationErrorCode)
    }

    @Test
    fun `should validate sd jwt with kb-jwt attached`() {
        val vc = loadSampleSdJwt("sdJwtWithKbJwtEdDSA.txt")
        val status = validator.validate(vc)
        assertEquals("", status.validationMessage)
        assertEquals("",status.validationErrorCode)
    }

    @Test
    fun `should validate sd jwt with kb-jwt attached with cnf in jwk format`() {
        val vc = loadSampleSdJwt("sdJwtWithKbJwtEs256kAndCnfBeingJwk.txt")
        val status = validator.validate(vc)
        assertEquals("", status.validationMessage)
        assertEquals("",status.validationErrorCode)
    }

    @Test
    fun `should fail for cnf kid not in did format`() {
        val vc = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJ2YytzZC1qd3QifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInZjdCI6InVybjpldWRpOnBpZDpkZToxIiwiaWF0IjoxNzU5ODk2MTU1LCJleHAiOjI1NDE3Mjk0MTAwMCwic3ViIjoidXNlcjEyMyIsIl9zZCI6WyJxLXhNRDBIbjFaVC1yc19UMmQyRXVHazNPVGluMUNqWVBrTU9JZDdBcFdVIiwibE9GU1hfZmtvYm9abWtCUDN4Vnl4d1ctZFNXV0did0pIX3FiTzRFdnBqMCIsIm9YWUNXRE85dEFhZWMxTDBpdXZVUlllVkFya1pmWGxXb0NIN3I4YWVDVUEiXSwiY25mIjp7ImtpZCI6Imh0dHBzOi8vaG9sZGVyLmV4YW1wbGUuY29tL2tleXMvMSJ9LCJfc2RfYWxnIjoic2hhLTI1NiJ9.MEQCIGi0VpKNYtj_ODtesOCVvvqJ2cUNHBRCLO4Luo0EDRjdAiBX2_PubKDMrZT0pAMdM5l8JtEJJ7QQW8soFI6quap2vA~WyJ6MjJaT05WUzREdkotd1pFbHJ6VEJnIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyIyeXRpSDdXa2ZjTk0zRXBfN1IzblpBIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyIwbS1fY3J2QVc2YUdfbGM2enAtTXdBIiwiZW1haWwiLCJqb2huLmRvZUBleGFtcGxlLmNvbSJd~eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJrYitqd3QifQ.eyJpYXQiOjE3NTk4OTYxNTUsImF1ZCI6Imh0dHBzOi8vdmVyaWZpZXIuZXhhbXBsZS5jb20iLCJub25jZSI6InJhbmRvbS1ub25jZS1HSXRpNmRSTElITmlGR0dQcmdjQTJBIiwic2RfaGFzaCI6IlZoR1k0MTFycVE4dW12ZHRfc2tuSjdaVWhaQU5UYW44QS01aEFPWm5OeUUifQ.MEUCIBjYtbtg2-joD4krmgavj6AjXQwgWmxPKelUXgn_M3hRAiEA23hIj4m8SAZG-dJstoJsHomIG0Qw0QnflRCWVQVcaho"
        val status = validator.validate(vc)
        assertEquals("Unsupported 'kid' format in 'cnf'. Only DID format is supported", status.validationMessage)
        assertEquals("ERR_INVALID_CNF_KID",status.validationErrorCode)
    }

    @Test
    fun `should fail for invalid KB-JWT signature`() {
        val vc = loadSampleSdJwt("sdJwtWithKbJwtEdDSA.txt")
        unmockkAll()
        // Tamper the KB-JWT's payload so the signature fails
        val parts = vc.split("~").toMutableList()
        val kbJwt = parts.last()
        val jwtParts = kbJwt.split(".")
        val payload = JSONObject(
            String(Base64.getUrlDecoder().decode(jwtParts[1]))
        )
        payload.put("aud", "tampered-audience")

        val modifiedPayload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payload.toString().toByteArray())

        val tamperedKbJwt = "${jwtParts[0]}.$modifiedPayload.${jwtParts[2]}"
        parts[parts.lastIndex] = tamperedKbJwt
        val tamperedVc = parts.joinToString("~")

        val status = validator.validate(tamperedVc)

        assertEquals("Signature verification failed for KB-JWT", status.validationMessage)
        assertEquals("ERR_INVALID_KB_SIGNATURE", status.validationErrorCode)
    }

    @Test
    fun `should fail when iat is missing in KB-JWT`() {
        val originalSdJwt = loadSampleSdJwt("sdJwtWithKbJwtEdDSA.txt")

        val parts = originalSdJwt.split("~")
        val originalKbJwt = parts.getOrNull(2) ?: error("KB-JWT not found in input")

        val modifiedKbJwt = modifyKbJwtPayload(originalKbJwt) { payload ->
            payload.remove("iat")
        }

        val tamperedVc = listOf(parts[0], parts[1], modifiedKbJwt).plus(parts.drop(3)).joinToString("~")

        val status = validator.validate(tamperedVc)

        assertEquals("ERR_MISSING_IAT", status.validationErrorCode)
        assertEquals("Missing 'iat' in Key Binding JWT", status.validationMessage)
    }

    @Test
    fun `should fail when nonce is missing in KB-JWT`() {
        val originalSdJwt = loadSampleSdJwt("sdJwtWithKbJwtEdDSA.txt")

        val parts = originalSdJwt.split("~")
        val originalKbJwt = parts.getOrNull(2) ?: error("KB-JWT not found")

        val modifiedKbJwt = modifyKbJwtPayload(originalKbJwt) { payload ->
            payload.remove("nonce")
        }

        val tamperedVc = listOf(parts[0], parts[1], modifiedKbJwt).plus(parts.drop(3)).joinToString("~")

        val status = validator.validate(tamperedVc)

        assertEquals("ERR_MISSING_NONCE", status.validationErrorCode)
        assertEquals("Missing 'nonce' in Key Binding JWT", status.validationMessage)
    }

    @Test
    fun `should fail when _sd_hash in KB-JWT does not match actual SD-JWT`() {
        val originalSdJwt = loadSampleSdJwt("sdJwtWithKbJwtEdDSA.txt")

        val parts = originalSdJwt.split("~").toMutableList()
        val originalKbJwt = parts[2]

        val modifiedKbJwt = modifyKbJwtPayload(originalKbJwt) { payload ->
            // invalid hash
            payload.put("sd_hash", "invalidHashValue")
        }

        parts[2] = modifiedKbJwt
        val tamperedVc = parts.joinToString("~")

        val status = validator.validate(tamperedVc)

        assertEquals("ERR_INVALID_SD_HASH", status.validationErrorCode)
    }

    @Test
    fun `should fail when KB-JWT alg is unsupported`() {
        val originalSdJwt = loadSampleSdJwt("sdJwtWithKbJwtEdDSA.txt")
        mockkConstructor(ES256KSignatureVerifierImpl::class)
        every { anyConstructed<ES256KSignatureVerifierImpl>().verify(any(), any(), any()) } returns true

        val parts = originalSdJwt.split("~")
        val originalKbJwt = parts.getOrNull(2)!!

        val modifiedKbJwt = modifyKbJwtHeader(originalKbJwt) { header ->
            header.put("alg", "unsupported-alg")
        }

        val tamperedVc = listOf(parts[0], parts[1], modifiedKbJwt).plus(parts.drop(3)).joinToString("~")
        val status = validator.validate(tamperedVc)

        assertEquals("ERR_INVALID_KB_JWT_ALG", status.validationErrorCode)
        assertEquals("Unsupported signature algorithm in Key Binding JWT: unsupported-alg", status.validationMessage)
    }
    @Test
    fun `should fail when alg is missing in KB-JWT header`() {
        val originalSdJwt = loadSampleSdJwt("sdJwtWithKbJwtEdDSA.txt")

        mockkConstructor(ES256KSignatureVerifierImpl::class)
        every { anyConstructed<ES256KSignatureVerifierImpl>().verify(any(), any(), any()) } returns true

        val parts = originalSdJwt.split("~")
        val originalKbJwt = parts.getOrNull(2) ?: error("KB-JWT not found")

        val modifiedKbJwt = modifyKbJwtHeader(originalKbJwt) { header ->
            header.remove("alg")
        }

        val tamperedVc = listOf(parts[0], parts[1], modifiedKbJwt).plus(parts.drop(3)).joinToString("~")

        val status = validator.validate(tamperedVc)

        assertEquals("ERR_MISSING_KB_JWT_ALG", status.validationErrorCode)
        assertEquals("Missing 'alg' in Key Binding JWT header", status.validationMessage)
    }

    @Test
    fun `should fail when typ is invalid in KB-JWT header`() {
        val originalSdJwt = loadSampleSdJwt("sdJwtWithKbJwtEdDSA.txt")

        mockkConstructor(ES256KSignatureVerifierImpl::class)
        every { anyConstructed<ES256KSignatureVerifierImpl>().verify(any(), any(), any()) } returns true

        val parts = originalSdJwt.split("~")
        val originalKbJwt = parts.getOrNull(2) ?: error("KB-JWT not found")

        val modifiedKbJwt = modifyKbJwtHeader(originalKbJwt) { header ->
            header.put("typ", "INVALID_TYP")
        }

        val tamperedVc = listOf(parts[0], parts[1], modifiedKbJwt).plus(parts.drop(3)).joinToString("~")

        val status = validator.validate(tamperedVc)

        assertEquals("ERR_INVALID_KB_JWT_TYP", status.validationErrorCode)
        assertEquals("Invalid 'typ' in KB-JWT header. Expected 'kb+jwt'", status.validationMessage)
    }

    @Test
    fun `should fail when cnf is not in supported format (supported - jwk, kid)`() {
        val vc = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJ2YytzZC1qd3QifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInZjdCI6InVybjpldWRpOnBpZDpkZToxIiwiaWF0IjoxNzU5ODk2MDg2LCJleHAiOjI1NDE3Mjk0MTAwMCwic3ViIjoidXNlcjEyMyIsIl9zZCI6WyJFR3k2Mkt2c282WnJ5WGlwbEZjN3l2WlJrMzdwMkdWSEdobnM2NWlsZHlZIiwici12U1J2cHZvX3JyZ2llbnRQb0N6RXM2RWpjSGQ4amROalN0S3ZkNjZ4VSIsInBrV2lTNDVHX240S3lLaDNKV0tTTGRaQTE0RFFzXzJuX2Mxdy16ZHNTQjgiXSwiY25mIjp7ImprdSI6Imh0dHBzOi8vYXR0YWNrZXIuY29tL2p3a3MuanNvbiJ9LCJfc2RfYWxnIjoic2hhLTI1NiJ9.MEQCIC1Yn_pkv_viLpis4SkUDMi8dCQaqoroOPZmhgeF1pjUAiBqgfNUVYibjO29zVs3m24fdl0WywHYSZhyYG9rAUMaUw~WyJUVU5wakpfOTBMekU3ajRqdnlQbzdRIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJ4MWt6YVVxM0JKMWhPX0VydmpLLUJnIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyJsY1JXbGl6SXVyTzhYUk9MQTlmMkNnIiwiZW1haWwiLCJqb2huLmRvZUBleGFtcGxlLmNvbSJd~eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJrYitqd3QifQ.eyJpYXQiOjE3NTk4OTYwODYsImF1ZCI6Imh0dHBzOi8vdmVyaWZpZXIuZXhhbXBsZS5jb20iLCJub25jZSI6InJhbmRvbS1ub25jZS14Y2RXNjFFVi1odVo1eXdxbVY5VjFBIiwic2RfaGFzaCI6IklVMWo5N2pfdjhKdWZILVZJM1E3WloxUzV5ekRCSkY2Rm9lcTg3NlNiRFUifQ.MEUCIG8J9w3SW5P5g-3c5cVavRxAb_9kPvYCCH6lXruXGyPgAiEAmDBUhCmojFERLd5MlFie-Kst3mJAoMX5A6HyczjcYxw"

        val status = validator.validate(vc)

        assertEquals("Missing supported key type in 'cnf': Supported 'kid', 'jwk'", status.validationMessage)
        assertEquals("ERR_INVALID_CNF_TYPE",status.validationErrorCode)
    }

    @Test
    fun `should validate plain SD-JWT when holder binding is not required`() {
        val vc = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        val status = validatePlainSdJwt(vc)
        assertEquals("", status.validationMessage)
        assertEquals("", status.validationErrorCode)
    }

    @Test
    fun `should reject plain SD-JWT when holder binding is required`() {
        val vc = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        val status = validator.validate(vc, validateKeyBindingJwt = true)
        assertEquals("Missing Key Binding JWT", status.validationMessage)
        assertEquals("ERR_MISSING_KB_JWT", status.validationErrorCode)
    }

    @Test
    fun `should reject SD-JWT without cnf when holder binding is required`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithKbJwtEdDSA.txt")) {
            it.remove("cnf")
        }
        val status = validator.validate(vc, validateKeyBindingJwt = true)
        assertEquals("Missing 'cnf' in SD-JWT payload", status.validationMessage)
        assertEquals("ERR_INVALID_CNF", status.validationErrorCode)
    }

    @Test
    fun `should validate SD-JWT with KB JWT when holder binding is not required`() {
        val vc = loadSampleSdJwt("sdJwtWithKbJwtEdDSA.txt")
        val status = validatePlainSdJwt(vc)
        assertEquals("", status.validationMessage)
        assertEquals("", status.validationErrorCode)
    }
}