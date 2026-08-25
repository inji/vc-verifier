package io.mosip.vercred.vcverifier.keyResolver.types.jwks

import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256K_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_PS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.P256
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.SECP256K1
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.constants.JwkParams
import io.mosip.vercred.vcverifier.keyResolver.getPublicKeyFromJWK
import java.security.PublicKey

private val PRIVATE_JWK_PARAMS = setOf("d", "p", "q", "dp", "dq", "qi", "k", "oth")

private data class KeyConstraint(val keyType: String, val curve: String? = null)

private val ALGORITHM_KEY_CONSTRAINTS = mapOf(
    JWS_ES256_SIGN_ALGO_CONST to KeyConstraint(JwkParams.KEY_TYPE_EC, P256),
    JWS_ES256K_SIGN_ALGO_CONST to KeyConstraint(JwkParams.KEY_TYPE_EC, SECP256K1),
    JWS_RS256_SIGN_ALGO_CONST to KeyConstraint(JwkParams.KEY_TYPE_RSA),
    JWS_PS256_SIGN_ALGO_CONST to KeyConstraint(JwkParams.KEY_TYPE_RSA),
    JWS_EDDSA_SIGN_ALGO_CONST to KeyConstraint(JwkParams.KEY_TYPE_OKP, ED25519_ALGORITHM)
)

internal fun selectKeyFromJwks(
    jwks: Map<*, *>,
    keyId: String?,
    algorithm: String? = null
): PublicKey {
    val keys = jwks[JwkParams.KEYS] as? List<*>
        ?: throw PublicKeyNotFoundException("JWKS 'keys' array not found")
    val publishedKeys = keys.filterIsInstance<Map<*, *>>()

    val candidates = if (keyId != null) {
        val exactMatches = publishedKeys.filter { it[JwkParams.KID] == keyId }
        when {
            // RFC 7517 4.5 only SHOULDs distinct 'kid' values; duplicates are rejected regardless for security
            exactMatches.size > 1 ->
                throw PublicKeyNotFoundException("Multiple keys found for kid=$keyId")
            exactMatches.size == 1 -> {
                val jwk = exactMatches.single()
                validateVerificationKey(jwk, algorithm)?.let {
                    throw PublicKeyResolutionFailedException(it)
                }
                return toPublicKey(jwk)
            }
            else -> publishedKeys.filter { it[JwkParams.KID] == null }.ifEmpty {
                throw PublicKeyNotFoundException("No matching key found for kid=$keyId")
            }
        }
    } else {
        publishedKeys
    }

    val validationErrors = candidates.map { it to validateVerificationKey(it, algorithm) }
    val usableKeys = validationErrors.filter { (_, problem) -> problem == null }.map { (jwk, _) -> jwk }

    if (usableKeys.size == 1) return toPublicKey(usableKeys.single())

    validationErrors.singleOrNull()?.second?.let { throw PublicKeyResolutionFailedException(it) }

    throw PublicKeyNotFoundException(
        if (usableKeys.isEmpty()) {
            "No usable verification key found in JWKS" + (algorithm?.let { " for alg=$it" } ?: "")
        } else {
            "Cannot select between ${usableKeys.size} usable keys in JWKS; " +
                if (keyId == null) "the JWT should carry a 'kid'"
                else "the issuer should publish a 'kid' for each key"
        }
    )
}

private fun toPublicKey(jwk: Map<*, *>): PublicKey {
    val keyType = jwk[JwkParams.KTY]?.toString()
        ?: throw PublicKeyNotFoundException("Missing 'kty' in JWK")

    @Suppress("UNCHECKED_CAST")
    return getPublicKeyFromJWK(jwk as Map<String, Any>, keyType)
}


private fun validateVerificationKey(jwk: Map<*, *>, algorithm: String?): String? {
    if (PRIVATE_JWK_PARAMS.any { it in jwk.keys }) {
        return "JWK must not contain private key material"
    }

    val jwkAlgorithm = jwk[JwkParams.ALG]?.toString()
    if (algorithm != null && jwkAlgorithm != null && jwkAlgorithm != algorithm) {
        return "JWK 'alg' does not match the expected algorithm"
    }

    val use = jwk[JwkParams.USE]?.toString()
    if (use != null && use != JwkParams.USE_SIGNATURE) {
        return "JWK 'use' must be '${JwkParams.USE_SIGNATURE}'"
    }

    val keyOps = jwk[JwkParams.KEY_OPS] as? List<*>
    if (keyOps != null && keyOps.none { it?.toString() == JwkParams.KEY_OP_VERIFY }) {
        return "JWK 'key_ops' must permit '${JwkParams.KEY_OP_VERIFY}'"
    }

    val constraint = algorithm?.let { ALGORITHM_KEY_CONSTRAINTS[it] } ?: return null
    if (jwk[JwkParams.KTY]?.toString() != constraint.keyType) {
        return "JWK 'kty' must be '${constraint.keyType}' for alg=$algorithm"
    }
    if (constraint.curve != null && jwk[JwkParams.CRV]?.toString() != constraint.curve) {
        return "JWK 'crv' must be '${constraint.curve}' for alg=$algorithm"
    }

    return null
}
