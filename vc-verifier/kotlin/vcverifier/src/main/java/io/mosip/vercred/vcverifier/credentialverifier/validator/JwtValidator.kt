package io.mosip.vercred.vcverifier.credentialverifier.validator

import com.nimbusds.jwt.SignedJWT
import io.mosip.vercred.vcverifier.data.ValidationStatus
import java.util.Date
import java.util.Base64

class JwtValidator {
    companion object {
        private const val CLOCK_SKEW_MS = 3000L
    }
    private val jwtRegex = Regex("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$")

    fun validate(credential: String): ValidationStatus {
        val trimmedCredential = credential.trim()

        try {
            val parts = trimmedCredential.split(".")
            if (parts.isNotEmpty()) {
                val headerJson = String(Base64.getUrlDecoder().decode(parts[0]))
                if (headerJson.contains("\"alg\":\"none\"", ignoreCase = true)) {
                    return ValidationStatus("JWT algorithm 'none' is not allowed", "INVALID_ALGORITHM")
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
            return ValidationStatus("Failed to parse JWT header: ${e.message}", "MALFORMED_INPUT")
        }

        if (!jwtRegex.matches(trimmedCredential)) {
            return ValidationStatus("Invalid characters or format in JWT", "MALFORMED_INPUT")
        }

        try {
            val signedJWT = SignedJWT.parse(trimmedCredential)
            
            signedJWT.header.type?.let { type ->
                if (type.toString() != "JWT") {
                    return ValidationStatus("typ header must be 'JWT', found: $type", "INVALID_HEADER")
                }
            }

            val claims = signedJWT.jwtClaimsSet
            if (claims.issuer.isNullOrBlank()) {
                return ValidationStatus("Missing required 'iss' (issuer) claim", "INVALID_VC_FORMAT")
            }

            val now = Date().time
            val expirationTime = claims.expirationTime
            if (expirationTime != null && now > (expirationTime.time + CLOCK_SKEW_MS)) {
                return ValidationStatus("VC has expired", "ERROR_CODE_VC_EXPIRED")
            }

            val notBeforeTime = claims.notBeforeTime
            if (notBeforeTime != null && now < (notBeforeTime.time - CLOCK_SKEW_MS)) {
                return ValidationStatus("VC is not yet valid", "ERROR_CODE_VC_NOT_YET_VALID")
            }

            val vcClaim = claims.getClaim("vc") as? Map<*, *>
            if (vcClaim == null || vcClaim["credentialSubject"] == null) {
                return ValidationStatus("Missing 'vc' or 'credentialSubject' claim", "INVALID_VC_FORMAT")
            }

            val sub = claims.subject
            val credentialSubjectId = (vcClaim["credentialSubject"] as? Map<*, *>)?.get("id")?.toString()
            if (sub != null && credentialSubjectId != null && sub != credentialSubjectId) {
                return ValidationStatus("Claim 'sub' must match 'credentialSubject.id'", "INVALID_VC_FORMAT")
            }

            val jti = claims.jwtid
            val vcId = vcClaim["id"]?.toString()
            if (jti != null && vcId != null && jti != vcId) {
                return ValidationStatus("Claim 'jti' must match 'vc.id'", "INVALID_VC_FORMAT")
            }

            return ValidationStatus("", "")
        } catch (e: Exception) {
            return ValidationStatus("Invalid JWT structure: ${e.message}", "INVALID_JWT")
        }
    }
}
