package io.mosip.vercred.vcverifier.credentialverifier.validator

import com.nimbusds.jwt.SignedJWT
import io.mosip.vercred.vcverifier.data.ValidationStatus
import java.util.Date

class JwtValidator {
    companion object {
        val SUCCESS = ValidationStatus("", "")
        private const val CLOCK_SKEW_MS = 60 * 1000L
    }
    private val jwtRegex = Regex("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$")

    fun validate(credential: String): ValidationStatus {
        val trimmedCredential = credential.trim()
        if (!jwtRegex.matches(trimmedCredential)) {
            return ValidationStatus("Invalid characters or format in JWT", "MALFORMED_INPUT")
        }
        try {
            val signedJWT = SignedJWT.parse(trimmedCredential)
            val claims = signedJWT.jwtClaimsSet
            val now = Date().time
            val expirationTime = claims.expirationTime
            if (expirationTime != null && now > (expirationTime.time + CLOCK_SKEW_MS)) {
                return ValidationStatus("VC has expired", "ERROR_CODE_VC_EXPIRED")
            }
            val notBeforeTime = claims.notBeforeTime
            if (notBeforeTime != null && now < (notBeforeTime.time - CLOCK_SKEW_MS)) {
                return ValidationStatus("VC is not yet valid", "ERROR_CODE_VC_NOT_YET_VALID")
            }
            if (claims.getClaim("vc") == null) {
                return ValidationStatus("Missing 'vc' claim in payload", "INVALID_VC_FORMAT")
            }
            return SUCCESS
        } catch (e: Exception) {
            return ValidationStatus("Invalid JWT structure: ${e.message}", "INVALID_JWT")
        }
    }
}
