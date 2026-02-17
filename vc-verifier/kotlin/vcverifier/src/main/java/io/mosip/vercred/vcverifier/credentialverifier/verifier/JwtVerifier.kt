package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.nimbusds.jose.JWSObject
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.utils.Util.verifyJwt
import java.net.URI

class JwtVerifier {
    /**
     * Verifies the cryptographic signature of a JWT-based Verifiable Credential.
     * Leverages centralized utility for cross-algorithm and cross-key support (RSA/EC/EdDSA).
     */
    fun verify(credential: String): Boolean {
        val jwsObject = JWSObject.parse(credential)
        val payload = jwsObject.payload.toJSONObject() 
            ?: throw IllegalArgumentException("JWT payload is not a valid JSON object")
        val issuer = payload["iss"]?.toString() 
            ?: throw IllegalArgumentException("Missing required 'iss' claim")
        val factory = PublicKeyResolverFactory()
        val publicKey = factory.get(URI.create(issuer))
        val isVerified = verifyJwt(
            credential, 
            publicKey, 
            jwsObject.header.algorithm.name
        )
        if (!isVerified) {
            throw SecurityException("Cryptographic signature verification failed. The token data has been tampered with.")
        }

        return true
    }
}
