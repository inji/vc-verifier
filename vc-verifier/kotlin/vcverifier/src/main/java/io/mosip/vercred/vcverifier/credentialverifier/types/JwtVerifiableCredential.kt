package io.mosip.vercred.vcverifier.credentialverifier.types

import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.validator.JwtValidator
import io.mosip.vercred.vcverifier.credentialverifier.verifier.JwtVerifier
import io.mosip.vercred.vcverifier.data.ValidationStatus

class JwtVerifiableCredential: VerifiableCredential {
    override fun validate(credential: String): ValidationStatus {
        return JwtValidator().validate(credential)
    }

    override fun verify(credential: String): Boolean {
        return JwtVerifier().verify(credential)
    }
}