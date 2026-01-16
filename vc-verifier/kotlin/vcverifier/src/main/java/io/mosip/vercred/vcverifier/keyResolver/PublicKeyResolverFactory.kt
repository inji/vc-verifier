package io.mosip.vercred.vcverifier.keyResolver

import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import io.mosip.vercred.vcverifier.keyResolver.types.http.HttpsPublicKeyResolver
import io.mosip.vercred.vcverifier.keyResolver.types.jwks.JwksPublicKeyResolver
import java.net.URI
import java.security.PublicKey


internal const val DID_PREFIX = "did:"
private const val HTTP_PREFIX = "http"

private const val JWKS_SUFFIX = "jwks.json"

class PublicKeyResolverFactory {

    fun get(verificationMethod: URI, keyId: String? = null): PublicKey {
        val verificationMethodStr = verificationMethod.toString()
        return when {
            verificationMethodStr.startsWith(DID_PREFIX) -> DidPublicKeyResolver().resolve(verificationMethod.toString())
            verificationMethodStr.startsWith(HTTP_PREFIX) && verificationMethodStr.endsWith(JWKS_SUFFIX) -> JwksPublicKeyResolver().resolve(verificationMethod.toString(),keyId)
            verificationMethodStr.startsWith(HTTP_PREFIX) -> HttpsPublicKeyResolver().resolve(verificationMethod.toString())
            else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
        }
    }
}