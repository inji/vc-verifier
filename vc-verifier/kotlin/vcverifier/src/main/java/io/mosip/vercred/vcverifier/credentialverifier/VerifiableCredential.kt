package io.mosip.vercred.vcverifier.credentialverifier

import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.data.ValidationStatus

interface VerifiableCredential {
    fun validate(credential: String): ValidationStatus
    fun verify(credential: String): Boolean
    fun checkStatus(credential: String, statusPurposes: List<String>?): Map<String, CredentialStatusResult> {
        throw UnsupportedOperationException("Credential status checking not supported for this credential format")
    }
}