package io.mosip.vercred.vcverifier.credentialverifier.validator

import com.nimbusds.jwt.SignedJWT
import io.mosip.vercred.vcverifier.data.ValidationStatus
import java.util.Date

class JwtValidator {
    companion object {
        // Fix - CodeRabbit: Define explicit success constant
        val SUCCESS = ValidationStatus("", "")
        // Fix - CodeRabbit: 60s tolerance for distributed clock skew
        private const val CLOCK_SKEW_MS = 60 * 1000L
    }

    // Regular expression for valid Base64URL JWT (three parts separated by dots)
    private val jwtRegex = Regex("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$")

    fun validate(credential: String): ValidationStatus {
        // 1. Strict Character Check
        // Fix - CodeRabbit: assign val normalized = credential.trim()
        val trimmedCredential = credential.trim()
        if (!jwtRegex.matches(trimmedCredential)) {
            return ValidationStatus("Invalid characters or format in JWT", "MALFORMED_INPUT")
        }

        // Fix - Structural change from 'return try' to standard try-catch to resolve Unit mismatch
        try {
            val signedJWT = SignedJWT.parse(trimmedCredential)
            val claims = signedJWT.jwtClaimsSet
            val now = Date().time
            
            // 2. Expiry Check
            val expirationTime = claims.expirationTime
            // Fix - CodeRabbit: Added skew tolerance to prevent false rejections
            if (expirationTime != null && now > (expirationTime.time + CLOCK_SKEW_MS)) {
                return ValidationStatus("VC has expired", "ERROR_CODE_VC_EXPIRED")
            }

            // 3. Not Before (nbf) Check
            val notBeforeTime = claims.notBeforeTime
            // Fix - CodeRabbit: Added skew tolerance to prevent false rejections
            if (notBeforeTime != null && now < (notBeforeTime.time - CLOCK_SKEW_MS)) {
                return ValidationStatus("VC is not yet valid", "ERROR_CODE_VC_NOT_YET_VALID")
            }

            // 4. W3C Spec Check
            if (claims.getClaim("vc") == null) {
                return ValidationStatus("Missing 'vc' claim in payload", "INVALID_VC_FORMAT")
            }

            // Success path
            return SUCCESS
        } catch (e: Exception) {
            // Error path
            return ValidationStatus("Invalid JWT structure: ${e.message}", "INVALID_JWT")
        }
    }
}