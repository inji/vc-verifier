package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.nimbusds.jose.JWSObject
import io.mosip.vercred.vcverifier.constants.DidMethod
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import io.mosip.vercred.vcverifier.keyResolver.types.jwks.SdJwtVcIssuerMetadataResolver
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import io.mosip.vercred.vcverifier.utils.DateUtils
import io.mosip.vercred.vcverifier.utils.Util
import io.mosip.vercred.vcverifier.utils.Util.verifyJwt
import java.security.PublicKey

private const val DID_SCHEME = "did:"
private const val HTTPS_SCHEME = "https://"
private const val MAX_X5C_CHAIN_LENGTH = 10
/**
 * DID methods accepted for the *issuer* key.
 *
 * `did:key` and `did:jwk` are self-certifying — the identifier *is* the key — which gives the
 * strongest possible integrity between the `iss` value and the verification key, as
 * draft-ietf-oauth-sd-jwt-vc-10 10.2 requires of an ecosystem-defined mechanism. What they do not
 * establish is *authenticity*: that the DID belongs to the Issuer it claims to be.
 *
 * TODO: authenticity belongs to a trusted issuer policy, which this library does not yet have.
 *  Section 3.5 requires the mechanism to be "permitted for the given Issuer according to policy",
 *  and 10.2 requires that an attacker cannot influence which mechanism is used for a given `iss`.
 *  Until a trust list exists, a valid signature proves only that the holder of the named key signed
 *  the credential, not that the Issuer is one the Verifier trusts. The same gap leaves `x5c`
 *  certificates unchained; one trust policy would close both.
 */
private val PERMITTED_ISSUER_DID_METHODS = setOf(DidMethod.WEB, DidMethod.KEY, DidMethod.JWK)

class SdJwtVerifier {

    fun verify(credential: String): Boolean {
        val parts = credential.split("~")
        val jwt = parts[0]
        return verifyJWTSignature(jwt)
    }

    private fun verifyJWTSignature(jwt: String): Boolean {
        val parts = jwt.split(".")
        require(parts.size == 3) { "Invalid JWT format" }

        val jwsObject = JWSObject.parse(jwt)
        val header = jwsObject.header
        val x5cChain = header.x509CertChain.orEmpty()
        val publicKey = if (x5cChain.isNotEmpty()) {
            getPublicKeyFromX5cChain(x5cChain.map { it.toString() })
        } else {
            resolvePublicKeyFromIssuer(
                issuerClaim(jwsObject),
                header.keyID,
                header.algorithm.name
            )
        }

        return verifyJwt(jwt, publicKey, header.algorithm.name)
    }

    private fun issuerClaim(jwsObject: JWSObject): String =
        jwsObject.payload.toJSONObject()?.get("iss") as? String
            ?: throw IllegalArgumentException(
                "JWT 'iss' claim is required when no 'x5c' is present in the JWT header"
            )

    internal fun resolvePublicKeyFromIssuer(
        issuer: String,
        keyId: String?,
        algorithm: String
    ): PublicKey = when {
        issuer.startsWith(DID_SCHEME) -> resolvePublicKeyFromDid(issuer, keyId)
        issuer.startsWith(HTTPS_SCHEME, ignoreCase = true) ->
            SdJwtVcIssuerMetadataResolver().resolve(issuer, keyId, algorithm)

        else -> throw IllegalArgumentException(
            "JWT 'iss' must be a DID or an HTTPS URL to resolve the issuer key"
        )
    }

    private fun resolvePublicKeyFromDid(issuer: String, keyId: String?): PublicKey {
        require(!issuer.contains(Regex("[/?#]"))) {
            "JWT 'iss' DID must not contain path, query, or fragment components"
        }
        val method = DidMethod.fromValue(issuer.removePrefix(DID_SCHEME).substringBefore(':'))
        require(method in PERMITTED_ISSUER_DID_METHODS) {
            "JWT 'iss' DID method is not supported for issuer keys. Supported: " +
                    PERMITTED_ISSUER_DID_METHODS.joinToString { "$DID_SCHEME${it.value}" }
        }
        requireNotNull(keyId) {
            "JWT 'kid' is required when resolving the issuer key from a DID"
        }
        val verificationMethod = when {
            keyId.startsWith("#") -> "$issuer$keyId"
            keyId.startsWith("$issuer#") -> keyId
            else -> throw IllegalArgumentException(
                "JWT 'kid' must be a fragment or an absolute DID URL controlled by JWT 'iss'"
            )
        }
        return DidPublicKeyResolver().resolve(verificationMethod)
    }

    /**
     * Returns the leaf certificate's key after checking that every certificate in the chain is
     * within its validity period, so an expired intermediate is rejected as well as an expired leaf.
     */
    private fun getPublicKeyFromX5cChain(x5cChain: List<String>): PublicKey {
        require(x5cChain.size <= MAX_X5C_CHAIN_LENGTH) {
            "JWT 'x5c' chain must not contain more than $MAX_X5C_CHAIN_LENGTH certificates"
        }
        val certificates = x5cChain.map {
            Util.toX509Certificate(Base64Decoder().decodeFromBase64(it))
        }
        certificates.forEach(DateUtils::validateCertificateValidity)
        return certificates.first().publicKey
    }
}