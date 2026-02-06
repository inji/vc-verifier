package io.mosip.vercred.vcverifier.credentialverifier.validator

import com.nimbusds.jwt.SignedJWT
import io.mosip.vercred.vcverifier.data.ValidationStatus
import java.util.Date

class JwtValidator {
    // Regular expression for valid Base64URL JWT (three parts separated by dots)
    private val jwtRegex = Regex("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$")

    fun validate(credential: String): ValidationStatus {
        // 1. Strict Character Check
        if (!jwtRegex.matches(credential.trim())) {
            return ValidationStatus("Invalid characters or format in JWT", "MALFORMED_INPUT")
        }

        return try {
            val signedJWT = SignedJWT.parse(credential)
            val claims = signedJWT.jwtClaimsSet
            val now = Date()
            
            // 2. Expiry Check
            val expirationTime = claims.expirationTime
            if (expirationTime != null && now.after(expirationTime)) {
                return ValidationStatus("VC has expired", "ERROR_CODE_VC_EXPIRED")
            }

            // 3. Not Before (nbf) Check
            val notBeforeTime = claims.notBeforeTime
            if (notBeforeTime != null && now.before(notBeforeTime)) {
                return ValidationStatus("VC is not yet valid", "ERROR_CODE_VC_NOT_YET_VALID")
            }

            // 4. W3C Spec Check
            if (claims.getClaim("vc") == null) {
                return ValidationStatus("Missing 'vc' claim in payload", "INVALID_VC_FORMAT")
            }

            ValidationStatus("", "") // Success
        } catch (e: Exception) {
            ValidationStatus("Invalid JWT structure: ${e.message}", "INVALID_JWT")
        }
    }
}