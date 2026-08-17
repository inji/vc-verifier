package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.nimbusds.jose.JWSObject
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import io.mosip.vercred.vcverifier.utils.Util
import io.mosip.vercred.vcverifier.utils.Util.verifyJwt
import java.security.PublicKey

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
        val certBase64 = jwsObject.header.x509CertChain?.firstOrNull()?.toString()
            ?: throw IllegalArgumentException("No X.509 certificate found in JWT header")

        val publicKey = getPublicKeyFromCertificate(certBase64)

        return verifyJwt(jwt, publicKey, jwsObject.header.algorithm.name)
    }

    private fun getPublicKeyFromCertificate(certBase64: String): PublicKey {
        val certificateBytes = Base64Decoder().decodeFromBase64(certBase64)
        val x509Certificate = Util.toX509Certificate(certificateBytes)
        val publicKey = x509Certificate.publicKey
        return publicKey
    }
}