package io.mosip.vercred.vcverifier.credentialverifier.types

import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.validator.CwtValidator
import io.mosip.vercred.vcverifier.credentialverifier.verifier.CwtVerifer
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.data.ValidationStatus

class CwtVerifiableCredential: VerifiableCredential {
    override fun validate(credential: String): ValidationStatus {
        return CwtValidator().validate(credential)
    }

    override fun verify(credential: String): Boolean {
        return CwtVerifer().verify(credential);
    }

    override fun checkStatus(credential: String, statusPurposes: List<String>?): List<CredentialStatusResult>? {
        return null;
    }
}