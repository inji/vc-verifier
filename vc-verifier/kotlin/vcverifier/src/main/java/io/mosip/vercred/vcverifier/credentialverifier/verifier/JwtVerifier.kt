package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import java.net.URI
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class JwtVerifier {
    /**
     * Verifies the cryptographic signature of a JWT-based Verifiable Credential.
     * Throws an Exception if the signature is mathematically invalid to ensure fail-closed security.
     */
    fun verify(credential: String): Boolean {
        // 1. Parse the JWT - will throw an exception if structure is invalid
        val jwsObject = JWSObject.parse(credential)
        
        // Fix for CodeRabbit: Use a strict allowlist of algorithms to prevent confusion attacks
        val alg = jwsObject.header.algorithm
        val allowedAlgorithms = setOf(
            com.nimbusds.jose.JWSAlgorithm.RS256,
            com.nimbusds.jose.JWSAlgorithm.RS384,
            com.nimbusds.jose.JWSAlgorithm.RS512,
            com.nimbusds.jose.JWSAlgorithm.ES256,
            com.nimbusds.jose.JWSAlgorithm.ES384,
            com.nimbusds.jose.JWSAlgorithm.ES512
        )
        if (alg !in allowedAlgorithms) {
            throw SecurityException("Unsupported or disallowed JWT algorithm: ${alg.name}")
        }

        // 2. Extract Issuer to resolve the correct public key
        // Fix for CodeRabbit: Added null-check for payload to prevent NPE
        val payload = jwsObject.payload.toJSONObject() 
            ?: throw IllegalArgumentException("JWT payload is not a valid JSON object")
        val issuer = payload["iss"]?.toString() 
            ?: throw IllegalArgumentException("Missing required 'iss' claim")

        // 3. Resolve Public Key (handles did:jwk and other Mosip-supported formats)
        // Fix for CodeRabbit: Removed unnecessary Elvis operator as factory.get throws on failure
        val factory = PublicKeyResolverFactory()
        val publicKey = factory.get(URI.create(issuer))

        // 4. Select the appropriate cryptographic verifier based on Key Algorithm
        val verifier = when (publicKey) {
            is ECPublicKey -> ECDSAVerifier(publicKey)
            is RSAPublicKey -> RSASSAVerifier(publicKey)
            else -> throw UnsupportedOperationException("Unsupported public key type: ${publicKey.algorithm}")
        }

        // 5. THE CORE CRYPTO CHECK
        // If the signature math fails, it throws an error.
        if (!jwsObject.verify(verifier)) {
            throw SecurityException("Cryptographic signature verification failed. The token data has been tampered with.")
        }

        return true
    }
}