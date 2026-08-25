package io.mosip.vercred.vcverifier.keyResolver.types.jwks

import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.networkManager.HttpMethod.GET
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.net.URI
import java.net.URISyntaxException
import java.security.PublicKey

private const val WELL_KNOWN_PREFIX = "/.well-known/jwt-vc-issuer"

internal class SdJwtVcIssuerMetadataResolver {

    fun resolve(issuer: String, keyId: String?, algorithm: String): PublicKey {
        val metadataUri = metadataUriFor(issuer)
        val metadata = sendHTTPRequest(metadataUri.toString(), GET)
            ?: throw PublicKeyNotFoundException("JWT VC Issuer Metadata response is null")

        if (metadata["issuer"] != issuer) {
            throw PublicKeyResolutionFailedException(
                "JWT VC Issuer Metadata 'issuer' must exactly match the JWT 'iss' claim"
            )
        }

        val inlineJwks = metadata["jwks"] as? Map<*, *>
        val jwksUri = metadata["jwks_uri"] as? String
        if ((inlineJwks == null) == (jwksUri == null)) {
            throw PublicKeyResolutionFailedException(
                "JWT VC Issuer Metadata must contain exactly one of 'jwks' or 'jwks_uri'"
            )
        }

        val jwks = inlineJwks
            ?: sendHTTPRequest(validateRemoteJwksUri(jwksUri!!).toString(), GET)
            ?: throw PublicKeyNotFoundException("JWKS response is null")

        return selectKeyFromJwks(jwks, keyId, algorithm)
    }

    internal fun metadataUriFor(issuer: String): URI {
        val uri = parseUri(issuer) {
            "JWT 'iss' must be an HTTPS URL without userinfo, query, or fragment"
        }
        if (!uri.isHttps() || uri.userInfo != null || uri.query != null || uri.fragment != null) {
            throw PublicKeyResolutionFailedException(
                "JWT 'iss' must be an HTTPS URL without userinfo, query, or fragment"
            )
        }

        val issuerPath = uri.rawPath.orEmpty().trimEnd('/')
        val host = uri.host.lowercase()
        val authority = if (uri.port == -1) host else "$host:${uri.port}"
        return URI("https://$authority$WELL_KNOWN_PREFIX$issuerPath")
    }

    private fun validateRemoteJwksUri(value: String): URI {
        val uri = parseUri(value) { "'jwks_uri' must be an HTTPS URL without userinfo or fragment" }
        if (!uri.isHttps() || uri.userInfo != null || uri.fragment != null) {
            throw PublicKeyResolutionFailedException(
                "'jwks_uri' must be an HTTPS URL without userinfo or fragment"
            )
        }
        return uri
    }

    /** The scheme is case-insensitive per RFC 3986, and [URI] preserves the case it was given. */
    private fun URI.isHttps() = scheme.equals("https", ignoreCase = true) && host != null

    private fun parseUri(value: String, message: () -> String): URI =
        try {
            URI(value)
        } catch (e: URISyntaxException) {
            throw PublicKeyResolutionFailedException(message()).apply { initCause(e) }
        }
}
