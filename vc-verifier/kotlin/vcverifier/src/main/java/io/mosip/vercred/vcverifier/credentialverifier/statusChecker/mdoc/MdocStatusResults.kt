package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.IETF_BITS_1
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PURPOSE_REVOCATION
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PURPOSE_SUSPENSION
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.data.MdocCredentialStatus
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import io.mosip.vercred.vcverifier.exception.StatusCheckException

internal object MdocStatusResults {

    fun statusResult(status: MdocCredentialStatus, bits: Int): Map<String, CredentialStatusResult> {
        return when (status) {
            MdocCredentialStatus.VALID -> if (bits == IETF_BITS_1) {
                mapOf(STATUS_PURPOSE_REVOCATION to CredentialStatusResult(true, null))
            } else {
                mapOf(
                    STATUS_PURPOSE_REVOCATION to CredentialStatusResult(true, null),
                    STATUS_PURPOSE_SUSPENSION to CredentialStatusResult(true, null)
                )
            }
            MdocCredentialStatus.INVALID ->
                mapOf(STATUS_PURPOSE_REVOCATION to CredentialStatusResult(false, null))
            MdocCredentialStatus.SUSPENDED ->
                mapOf(STATUS_PURPOSE_SUSPENSION to CredentialStatusResult(false, null))
        }
    }

    fun supportedPurposes(
        results: Map<String, CredentialStatusResult>,
        statusPurposes: List<String>?
    ): Map<String, CredentialStatusResult> {
        if (statusPurposes.isNullOrEmpty()) {
            return results
        }
        val supported = statusPurposes.map { it.lowercase() }.toSet()
        return results.filterKeys { it.lowercase() in supported }
    }

    fun failure(errorCode: String, errorMessage: String?): Map<String, CredentialStatusResult> {
        val result = CredentialStatusResult(
            false,
            StatusCheckException(errorMessage ?: errorCode, toErrorCode(errorCode))
        )
        return mapOf(
            STATUS_PURPOSE_REVOCATION to result,
            STATUS_PURPOSE_SUSPENSION to result
        )
    }

    private fun toErrorCode(code: String): StatusCheckErrorCode {
        return runCatching { StatusCheckErrorCode.valueOf(code) }
            .getOrDefault(StatusCheckErrorCode.UNKNOWN_ERROR)
    }
}
