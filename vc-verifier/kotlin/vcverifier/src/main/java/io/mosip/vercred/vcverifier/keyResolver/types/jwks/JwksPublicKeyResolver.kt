package io.mosip.vercred.vcverifier.keyResolver.types.jwks

import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolver
import io.mosip.vercred.vcverifier.networkManager.HttpMethod.GET
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.security.PublicKey

class JwksPublicKeyResolver : PublicKeyResolver {

    override fun resolve(uri: String, keyId: String?): PublicKey {
        try {
            val response = sendHTTPRequest(uri, GET)
                ?: throw PublicKeyNotFoundException("JWKS response is null")

            return selectKeyFromJwks(response, keyId)
        } catch (e: Exception) {
            throw if (e is PublicKeyNotFoundException) e
            else PublicKeyNotFoundException("Failed to resolve JWKS public key: ${e.message}").apply { initCause(e) }
        }
    }
}
