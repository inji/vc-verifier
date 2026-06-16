package io.mosip.vercred.vcverifier.credentialverifier.validator

import com.authlete.sd.Disclosure
import com.authlete.sd.SDJWT
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_PROCESSING_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DISCLOSURE_CLAIM_NAME
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DISCLOSURE_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DISCLOSURE_STRUCTURE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_JWT_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_KB_JWT_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING_KB_JWT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VCT_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING_VCT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_PROCESSING_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DISCLOSURE_CLAIM_NAME
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DISCLOSURE_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DISCLOSURE_STRUCTURE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_JWT_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_KB_JWT_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_KB_JWT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VCT_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_VCT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXCEPTION_DURING_VALIDATION
import io.mosip.vercred.vcverifier.data.ValidationStatus
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.keyResolver.DID_PREFIX
import io.mosip.vercred.vcverifier.keyResolver.jwkToPublicKey
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import io.mosip.vercred.vcverifier.utils.Base64Encoder
import io.mosip.vercred.vcverifier.utils.DateUtils
import io.mosip.vercred.vcverifier.utils.DateUtils.formatEpochSecondsToIsoUtc
import io.mosip.vercred.vcverifier.utils.Util
import io.mosip.vercred.vcverifier.utils.Util.SUPPORTED_JWS_ALGORITHMS
import io.mosip.vercred.vcverifier.utils.Util.isValidUri
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.PublicKey

class SdJwtValidator {
    companion object {
        const val HASH_ALG_SHA_256 = "sha-256"
        const val HASH_ALG_SHA_384 = "sha-384"
        const val HASH_ALG_SHA_512 = "sha-512"
        private val SUPPORTED_SD_HASH_ALGORITHMS = setOf(HASH_ALG_SHA_256, HASH_ALG_SHA_384,
            HASH_ALG_SHA_512)
        private val SUPPORTED_CNF_KEY_OBJECT_TYPES = setOf("kid", "jwk")
        private val HASH_LENGTHS = mapOf(
            HASH_ALG_SHA_256 to 32,
            HASH_ALG_SHA_384 to 48,
            HASH_ALG_SHA_512 to 64
        )
        private val VALID_JWT_TYPES = setOf("vc+sd-jwt", "dc+sd-jwt")
    }

    fun validate(sdJwt: String, validateKeyBindingJwt: Boolean = true): ValidationStatus {
        return try {
            validateAndProcess(sdJwt, validateKeyBindingJwt)
        } catch (e: ValidationException) {
            ValidationStatus(e.errorMessage, e.errorCode)
        } catch (e: Exception) {
            ValidationStatus(
                "$EXCEPTION_DURING_VALIDATION${e.message}",
                "${ERROR_CODE_INVALID}UNKNOWN"
            )
        }
    }

    private fun validateAndProcess(credential: String, validateKeyBindingJwt: Boolean): ValidationStatus {
        if (credential.isBlank()) {
            throw ValidationException(ERROR_MESSAGE_EMPTY_VC_JSON, ERROR_CODE_EMPTY_VC_JSON)
        }
        val sdJwt = SDJWT.parse(credential)
        val credentialJwt = sdJwt.credentialJwt
        val disclosures = sdJwt.disclosures
        val keyBindingJwt = sdJwt.bindingJwt

        validateSdJwtStructure(credentialJwt, disclosures, validateKeyBindingJwt)
        if (validateKeyBindingJwt) {
            val kbJwt = keyBindingJwt
                ?: throw ValidationException(ERROR_MESSAGE_MISSING_KB_JWT, ERROR_CODE_MISSING_KB_JWT)
            this.validateKeyBindingJwt(kbJwt, sdJwt)
        }

        return ValidationStatus("", "")
    }

    private fun validateSdJwtStructure(credentialJwt: String, disclosures: List<Disclosure>, validateKeyBindingJwt: Boolean) {
        val jwtParts = credentialJwt.split(".")
        if (jwtParts.size != 3) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_JWT_FORMAT,
                ERROR_CODE_INVALID_JWT_FORMAT
            )
        }
        val header = decodeBase64Json(jwtParts[0])
        val payload = decodeBase64Json(jwtParts[1])
        val payloadMap = jacksonObjectMapper().readValue(payload, Map::class.java)

        validateHeader(JSONObject(header))
        validatePayload(JSONObject(payload), validateKeyBindingJwt)
        validateDisclosures(disclosures, payloadMap)
    }

    private fun validateHeader(header: JSONObject) {
        val alg = header.optString("alg", "")
        if (alg.isBlank() || alg.equals("none", ignoreCase = true)) {
            throw ValidationException(
                "Missing or invalid 'alg' in JWT header",
                "${ERROR_CODE_INVALID}ALG"
            )
        }

        val typ = header.optString("typ", "")
        if (typ !in VALID_JWT_TYPES) {
            throw ValidationException(
                "Unsupported or missing 'typ' in JWT header",
                "${ERROR_CODE_INVALID}TYP"
            )
        }
    }

    private fun validatePayload(payload: JSONObject, validateKeyBindingJwt: Boolean = false) {
        validateRequiredClaims(payload)
        validateTimeClaims(payload)
        validateUriClaims(payload)
        validateConfirmationClaim(payload, validateKeyBindingJwt)
    }

    private fun validateDisclosures(disclosures: List<Disclosure>, payload: Map<*, *>) {
        validateDisclosureFormat(disclosures)
        val hashAlg = (payload["_sd_alg"] as? String) ?: HASH_ALG_SHA_256
        val digestToDisclosure = disclosures.associateBy { it.digest(hashAlg) }
        val allSdDigests = mutableSetOf<String>()
        validateDisclosureSha(payload, digestToDisclosure, allSdDigests, hashAlg)
        val isAllDisclosureDigestPresent = digestToDisclosure.keys.all { it in allSdDigests }
        if (!isAllDisclosureDigestPresent)
            throw ValidationException(
                "Digest value of all disclosures must be present in the '_sd' claim of payload",
                "${ERROR_CODE_INVALID}DISCLOSURE"
            )

    }

    private fun validateRequiredClaims(payload: JSONObject) {
        val vct = payload.optString("vct", "")
        if (vct.isBlank()) {
            throw ValidationException(ERROR_MESSAGE_MISSING_VCT, ERROR_CODE_MISSING_VCT)
        }

        if (":" in vct && !isValidUri(vct)) {
            throw ValidationException(ERROR_MESSAGE_INVALID_VCT_URI, ERROR_CODE_INVALID_VCT_URI)
        }

        val iss = payload.opt("iss")

        iss?.let { value ->
            if (value !is String || value.isBlank()) {
                throw ValidationException(
                    "Invalid 'iss' claim: $iss",
                    "${ERROR_CODE_INVALID}ISS"
                )
            }
        }

        val hashAlg = payload.optString("_sd_alg", HASH_ALG_SHA_256)

        if (hashAlg !in SUPPORTED_SD_HASH_ALGORITHMS) {
            throw ValidationException(
                "Unsupported _sd_alg: $hashAlg. Allowed: $SUPPORTED_SD_HASH_ALGORITHMS",
                "${ERROR_CODE_INVALID}SD_ALG"
            )
        }
    }

    private fun validateTimeClaims(payload: JSONObject) {
        payload.optLong("iat", -1).takeIf { it > 0 }?.let { iat ->
            if (DateUtils.isFutureDateWithTolerance(formatEpochSecondsToIsoUtc(iat))) {
                throw ValidationException(
                    ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE,
                    ERROR_CODE_CURRENT_DATE_BEFORE_ISSUANCE_DATE
                )
            }
        }

        payload.optLong("nbf", -1).takeIf { it > 0 }?.let { nbf ->
            if (DateUtils.isFutureDateWithTolerance(formatEpochSecondsToIsoUtc(nbf))) {
                throw ValidationException(
                    ERROR_CURRENT_DATE_BEFORE_PROCESSING_DATE,
                    ERROR_CODE_CURRENT_DATE_BEFORE_PROCESSING_DATE
                )
            }
        }

        payload.optLong("exp", -1).takeIf { it > 0 }?.let { exp ->
            if (DateUtils.isVCExpired(formatEpochSecondsToIsoUtc(exp))) {
                throw ValidationException(ERROR_MESSAGE_VC_EXPIRED, ERROR_CODE_VC_EXPIRED)
            }
        }
    }

    private fun validateUriClaims(payload: JSONObject) {
        listOf("aud", "nonce").forEach { field ->
            payload.optString(field, "").takeIf { it.isNotBlank() }
                ?.let { value ->
                    if (":" in value && !isValidUri(value)) {
                        throw ValidationException(
                            ERROR_INVALID_URI + value,
                            "${ERROR_CODE_INVALID}${field.uppercase()}"
                        )
                    }
                }
        }
    }

    private fun validateConfirmationClaim(payload: JSONObject, requireHolderBinding: Boolean = false) {
        val cnf = payload.optJSONObject("cnf")
        if (requireHolderBinding) {
            if (cnf == null) {
                throw ValidationException("Missing 'cnf' in SD-JWT payload", "${ERROR_CODE_INVALID}CNF")
            }
            val hasSupportedKey = SUPPORTED_CNF_KEY_OBJECT_TYPES.any { cnf.has(it) }
            if (!hasSupportedKey) {
                throw ValidationException(
                    "Missing supported key type in 'cnf': Supported 'kid', 'jwk'",
                    "${ERROR_CODE_INVALID}CNF_TYPE"
                )
            }
        }
        cnf?.let {
            if (it.has("jwk") && it.has("kid")) {
                throw ValidationException(
                    "Invalid 'cnf' object: must contain either 'jwk' or 'kid'",
                    "${ERROR_CODE_INVALID}CNF"
                )
            }
        }
    }

    private fun validateDisclosureFormat(disclosures: List<Disclosure>) {
        disclosures.forEachIndexed { index, encodedDisclosure ->
            val jsonArray = try {
                val decodedBytes = Base64Decoder().decodeFromBase64Url(encodedDisclosure.disclosure)
                JSONArray(String(decodedBytes))
            } catch (e: Exception) {
                throw ValidationException(
                    "$ERROR_MESSAGE_INVALID_DISCLOSURE_FORMAT at index $index",
                    ERROR_CODE_INVALID_DISCLOSURE_FORMAT
                )
            }

            when (jsonArray.length()) {
                2 -> { /* Valid array disclosure */
                }

                3 -> validateObjectDisclosure(jsonArray, index)
                else -> throw ValidationException(
                    "$ERROR_MESSAGE_INVALID_DISCLOSURE_STRUCTURE at index $index",
                    ERROR_CODE_INVALID_DISCLOSURE_STRUCTURE
                )
            }
        }
    }

    private fun validateObjectDisclosure(jsonArray: JSONArray, index: Int) {
        val name = jsonArray.optString(1, null)
        if (name == null || name.startsWith("_")) {
            throw ValidationException(
                "$ERROR_MESSAGE_INVALID_DISCLOSURE_CLAIM_NAME at index $index",
                ERROR_CODE_INVALID_DISCLOSURE_CLAIM_NAME
            )
        }
    }

    private fun validateDisclosureSha(
        node: Any?,
        digestToDisclosure: Map<String, Disclosure>,
        allSdDigests: MutableSet<String>,
        hashAlg: String
    ): Any? {
        return when (node) {
            is Map<*, *> -> {
                val mutableNode = node.toMutableMap() as MutableMap<String, Any?>
                (mutableNode["_sd"] as? List<*>)?.forEach { digest ->
                    val digestStr = digest as? String ?: return@forEach
                    validateDigest(digest, hashAlg)
                    allSdDigests += digestStr
                    val disclosure = digestToDisclosure[digestStr] ?: return@forEach
                    val claimName = disclosure.claimName
                    val claimValue = disclosure.claimValue
                    if (!mutableNode.containsKey(claimName)) {
                        mutableNode[claimName] = claimValue
                    }
                }
                mutableNode.remove("_sd")

                for ((key, value) in mutableNode) {
                    mutableNode[key] =
                        validateDisclosureSha(value, digestToDisclosure, allSdDigests, hashAlg)
                }
                mutableNode
            }

            is List<*> -> {
                node.map { item ->
                    validateDisclosureSha(item, digestToDisclosure, allSdDigests, hashAlg)
                }
            }

            else -> {
                node
            }
        }
    }

    private fun validateDigest(digest: String, sdAlg: String) {
        val expectedLength = HASH_LENGTHS[sdAlg.lowercase()]
            ?: throw ValidationException(
                "Unsupported digest algorithm: $sdAlg",
                "${ERROR_CODE_INVALID}ALG"
            )
        if (digest.isBlank()) {
            throw ValidationException(
                "Invalid digest: must be a non-empty string",
                "${ERROR_CODE_INVALID}DIGEST"
            )
        }

        val decoded: ByteArray
        try {
            decoded = Base64Decoder().decodeFromBase64Url(digest)
        } catch (e: Exception) {
            throw ValidationException(
                "Invalid base64url encoding in digest: $digest ${e.message}",
                "${ERROR_CODE_INVALID}DIGEST"
            )
        }
        if (decoded.size != expectedLength) {
            throw ValidationException(
                "Invalid digest length of digest: expected $expectedLength bytes, got ${decoded.size}",
                "${ERROR_CODE_INVALID}DIGEST"
            )
        }

    }

    private fun validateKeyBindingJwt(kbJwt: String, sdJwt: SDJWT) {
        val parts = kbJwt.split(".")
        if (parts.size != 3) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_KB_JWT_FORMAT,
                ERROR_CODE_INVALID_KB_JWT_FORMAT
            )
        }

        val payload = JSONObject(decodeBase64Json(parts[1]))
        validateKeyBindingHeader(kbJwt)
        verifyKeyBindingSignature(kbJwt,sdJwt)
        validateKeyBindingPayload(payload, sdJwt)

    }

    private fun validateKeyBindingHeader(kbJwt: String) {
        val parts = kbJwt.split(".")
        val headerPart = parts[0]
        val headerJsonString = try {
            decodeBase64Json(headerPart)
        } catch (e: IllegalArgumentException) {
            throw ValidationException( "Failed to decode KB-JWT header","${ERROR_CODE_INVALID}KB_JWT_HEADER")
        }

        val header = try {
            JSONObject(headerJsonString)
        } catch (e: Exception) {
            throw ValidationException( "Failed to decode KB-JWT header","${ERROR_CODE_INVALID}KB_JWT_HEADER")
        }

        val alg = header.optString("alg")
        if (alg.isNullOrBlank()) {
            throw ValidationException( "Missing 'alg' in Key Binding JWT header","${ERROR_CODE_MISSING}KB_JWT_ALG")
        }

        if (!SUPPORTED_JWS_ALGORITHMS.contains(alg)) {
            throw ValidationException( "Unsupported signature algorithm in Key Binding JWT: $alg", "${ERROR_CODE_INVALID}KB_JWT_ALG")
        }

        val typ = header.optString("typ")
        if (typ != "kb+jwt") {
            throw ValidationException( "Invalid 'typ' in KB-JWT header. Expected 'kb+jwt'","${ERROR_CODE_INVALID}KB_JWT_TYP")
        }
    }


    private fun verifyKeyBindingSignature(kbJwt: String, sdJwt: SDJWT) {
        val parts = kbJwt.split(".")
        val kbJwtHeader = JSONObject(decodeBase64Json(parts[0]))
        val algorithm = kbJwtHeader["alg"] as? String

        val jwtParts = sdJwt.credentialJwt.split(".")

        val payloadJson = decodeBase64Json(jwtParts[1])
        val payload = JSONObject(payloadJson)

        val cnf = payload.optJSONObject("cnf")
            ?: throw ValidationException("Missing 'cnf' in SD-JWT payload", "${ERROR_CODE_INVALID}CNF")

        val cnfKey = SUPPORTED_CNF_KEY_OBJECT_TYPES.firstOrNull { cnf.has(it) }
            ?: throw ValidationException("Missing supported key type in 'cnf': Supported 'kid', 'jwk'", "${ERROR_CODE_INVALID}CNF_TYPE")


        val publicKey : PublicKey = if (cnfKey == "kid") {
            val kid = cnf.getString(cnfKey).trimEnd('=')
            if( !kid.startsWith(DID_PREFIX)) {
                throw ValidationException("Unsupported 'kid' format in 'cnf'. Only DID format is supported", "${ERROR_CODE_INVALID}CNF_KID")
            }
            DidPublicKeyResolver().resolve(kid)
        } else {
            val jwkJson = cnf.getJSONObject("jwk").toString()

            jwkToPublicKey(jwkJson)
        }

        val isValid = Util.verifyJwt(kbJwt, publicKey, algorithm!!)
        if (!isValid) {
            throw ValidationException("Signature verification failed for KB-JWT", "${ERROR_CODE_INVALID}KB_SIGNATURE")
        }
    }


    private fun validateKeyBindingPayload(payload: JSONObject, sdJwt: SDJWT) {
        val requiredFields = listOf("aud", "nonce", "sd_hash", "iat")

        requiredFields.forEach { field ->
            if (!payload.has(field)) {
                throw ValidationException(
                    "Missing '$field' in Key Binding JWT",
                    "${ERROR_CODE_MISSING}${field.uppercase()}"
                )
            }
        }

        val aud = payload.optString("aud")
        if (aud.isBlank()) {
            throw ValidationException(
                "'aud' in Key Binding JWT must be a non-empty string",
                "${ERROR_CODE_INVALID}AUD"
            )
        }

        if (":" in aud && !isValidUri(aud)) {
            throw ValidationException(
                "'aud' in Key Binding JWT must be a valid URI when containing ':'",
                "${ERROR_CODE_INVALID}AUD"
            )
        }

        val nonce = payload.optString("nonce")
        if (nonce.isBlank()) {
            throw ValidationException(
                "'nonce' in Key Binding JWT must be a non-empty string",
                "${ERROR_CODE_INVALID}NONCE"
            )
        }

        val iat = payload.optLong("iat", -1)
        if (iat <= 0) {
            throw ValidationException(
                "Missing or invalid 'iat' in Key Binding JWT",
                "${ERROR_CODE_INVALID}KB_JWT_IAT"
            )
        }

        val sdHash = payload.optString("sd_hash")
        if (sdHash.isBlank()) {
            throw ValidationException(
                "Missing or blank 'sd_hash' in Key Binding JWT",
                "${ERROR_CODE_INVALID}SD_HASH"
            )
        }
        validateSdHash(sdJwt, sdHash)
    }

    private fun validateSdHash(sdJwt: SDJWT, expectedHash: String) {
        val sdAlg = sdJwt.hashAlgorithm ?: "sha-256"
        val combinedSdJwt = buildString {
            append(sdJwt.credentialJwt).append("~")
            sdJwt.disclosures.forEach { append(it.disclosure).append("~") }
        }

        val digest = MessageDigest.getInstance(sdAlg)
            .digest(combinedSdJwt.toByteArray(StandardCharsets.US_ASCII))

        val actualHash = Base64Encoder().encodeToBase64Url(digest)

        if (actualHash != expectedHash) {
            throw ValidationException(
                "Key Binding JWT sd_hash mismatch. Expected: $expectedHash, Computed: $actualHash",
                "${ERROR_CODE_INVALID}SD_HASH"
            )
        }
    }

    private fun decodeBase64Json(encoded: String): String {
        val decodedBytes = Base64Decoder().decodeFromBase64Url(encoded)
        return String(decodedBytes)
    }
}