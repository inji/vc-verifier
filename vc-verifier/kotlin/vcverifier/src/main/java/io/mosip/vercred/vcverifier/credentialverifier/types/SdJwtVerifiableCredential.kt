package io.mosip.vercred.vcverifier.credentialverifier.types

import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.validator.SdJwtValidator
import io.mosip.vercred.vcverifier.credentialverifier.verifier.SdJwtVerifier
import io.mosip.vercred.vcverifier.data.ValidationStatus

class SdJwtVerifiableCredential: VerifiableCredential {
    override fun validate(credential: String, validateKeyBindingJwt: Boolean): ValidationStatus {
        return SdJwtValidator().validate(credential, validateKeyBindingJwt)
    }

    override fun verify(credential: String): Boolean {
        return SdJwtVerifier().verify(credential)
    }
}