package io.mosip.vercred.vcverifier.keyResolver.types.jwks

import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolver
import io.mosip.vercred.vcverifier.keyResolver.getPublicKeyFromJWK
import io.mosip.vercred.vcverifier.networkManager.HttpMethod.GET
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.security.PublicKey
import java.util.logging.Logger

class JwksPublicKeyResolver : PublicKeyResolver {

    private val logger = Logger.getLogger(JwksPublicKeyResolver::class.java.name)

    override fun resolve(uri: String, keyId: String?): PublicKey {
        try {
            val response = sendHTTPRequest(uri, GET)
                ?: throw PublicKeyNotFoundException("JWKS response is null")

            val keys = response["keys"] as? List<*>
                ?: throw PublicKeyNotFoundException("JWKS 'keys' array not found")

            val jwk = keys
                .filterIsInstance<Map<String, Any>>()
                .firstOrNull { keyId == null || it["kid"] == keyId }
                ?: throw PublicKeyNotFoundException("No matching key found for kid=$keyId")

            val kty = jwk["kty"]?.toString()
                ?: throw PublicKeyNotFoundException("Missing 'kty' in JWK")

            return getPublicKeyFromJWK(jwk, kty)
        } catch (e: Exception) {
            logger.severe("Error fetching public key string $e")
            throw PublicKeyNotFoundException("Public key string not found")
        }
    }

    companion object
}