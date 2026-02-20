package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.nimbusds.jose.JWSObject
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.utils.Util.verifyJwt
import java.net.URI

class JwtVerifier {
    /**
     * Verifies the cryptographic signature of a JWT-based Verifiable Credential.
     * Aligns with RFC 7515 by prioritizing JWS header for key identification.
     */
    fun verify(credential: String): Boolean {
        val jwsObject = JWSObject.parse(credential)
        val header = jwsObject.header
        val payload = jwsObject.payload.toJSONObject() 
            ?: throw IllegalArgumentException("JWT payload is not a valid JSON object")

        val kid = header.keyID ?: header.jwk?.keyID
        val issuerClaim = payload["iss"]?.toString()

        val issuerUri = when {
            kid != null -> URI.create(kid) 
            issuerClaim != null -> URI.create(issuerClaim) 
            else -> throw IllegalArgumentException("Missing key identification hint in header (kid, jwk) or payload (iss)")
        }

        val factory = PublicKeyResolverFactory()
        val publicKey = factory.get(issuerUri)
        
        val isVerified = verifyJwt(
            credential, 
            publicKey, 
            header.algorithm.name
        )
        
        if (!isVerified) {
            throw SecurityException("Cryptographic signature verification failed. The token data has been tampered with.")
        }

        return true
    }
}
