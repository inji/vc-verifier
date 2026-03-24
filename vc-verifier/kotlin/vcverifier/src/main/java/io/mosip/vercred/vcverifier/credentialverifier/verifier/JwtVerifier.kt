package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.jwk.AsymmetricJWK
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.utils.Util.verifyJwt
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import java.net.URI
import java.util.logging.Logger

class JwtVerifier {

    private val factory = PublicKeyResolverFactory()
    private val logger = Logger.getLogger(JwtVerifier::class.java.name)

    /**
     * Verifies the cryptographic signature of a JWT-based Verifiable Credential.
     * Aligns with OID4VCI and RFC 7515.
     */
    fun verify(credential: String): Boolean {
        return try {
            val jwsObject = JWSObject.parse(credential)
            val header = jwsObject.header
            val payload = jwsObject.payload.toJSONObject()
                ?: throw IllegalArgumentException("JWT payload is not a valid JSON object")

            val publicKey = if (header.jwk != null) {
                val asymmetricJwk = header.jwk as? AsymmetricJWK 
                    ?: throw IllegalArgumentException("Embedded JWK is not an asymmetric key")
                asymmetricJwk.toPublicKey()
            } else {
                val jkuString = header.toJSONObject()["jku"]?.toString()
                val kid = header.keyID
                val issuerClaim = payload["iss"]?.toString()

                val verificationUri = when {
                    jkuString != null -> URI.create(jkuString)
                    kid != null && (kid.startsWith("did:") || kid.startsWith("http")) -> URI.create(kid)
                    kid != null && !issuerClaim.isNullOrBlank() && issuerClaim.startsWith("did:") -> {
                        val separator = if (kid.startsWith("#")) "" else "#"
                        URI.create("$issuerClaim$separator$kid")
                    }
                    !issuerClaim.isNullOrBlank() -> URI.create(issuerClaim)
                    else -> throw IllegalArgumentException("Missing key identification hint (jku, kid, iss, or embedded jwk).")
                }
                factory.get(verificationUri, kid)
            }

            val isVerified = verifyJwt(
                credential,
                publicKey,
                header.algorithm.name
            )
            
            if (!isVerified) {
                logger.severe("Cryptographic signature verification failed. The token data has been tampered with.")
            }
            
            isVerified

        } catch (e: SignatureVerificationException) {
            logger.severe("Cryptographic signature verification failed: ${e.message}")
            false
        } catch (e: Exception) {
            logger.severe("JWT Verification Error: ${e.message}")
            false
        }
    }
}
