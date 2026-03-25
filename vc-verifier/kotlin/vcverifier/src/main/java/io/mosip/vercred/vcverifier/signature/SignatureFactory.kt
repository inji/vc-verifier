package io.mosip.vercred.vcverifier.signature

import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256K_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_PS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import io.mosip.vercred.vcverifier.signature.impl.ES256KSignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.PS256SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.RS256SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.ES256SignatureVerifierImpl

class SignatureFactory {

    fun get(signatureAlgorithm: String): SignatureVerifier {
        return when (signatureAlgorithm) {
            JWS_PS256_SIGN_ALGO_CONST -> PS256SignatureVerifierImpl()
            JWS_RS256_SIGN_ALGO_CONST -> RS256SignatureVerifierImpl()
            JWS_EDDSA_SIGN_ALGO_CONST -> ED25519SignatureVerifierImpl()
            JWS_ES256K_SIGN_ALGO_CONST -> ES256KSignatureVerifierImpl()
            JWS_ES256_SIGN_ALGO_CONST -> ES256SignatureVerifierImpl()
            else -> throw SignatureNotSupportedException("Unsupported jws signature algorithm")
        }
    }
}
