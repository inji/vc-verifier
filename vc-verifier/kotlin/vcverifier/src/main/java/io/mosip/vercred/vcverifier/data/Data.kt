package io.mosip.vercred.vcverifier.data

import io.mosip.vercred.vcverifier.exception.StatusCheckException

data class VerificationResult(
    var verificationStatus: Boolean,
    var verificationMessage: String = "",
    var verificationErrorCode: String

)

data class PresentationVerificationResult(
    var proofVerificationStatus: VPVerificationStatus,
    var vcResults: List<VCResult>
)

data class PresentationResultWithCredentialStatus(
    var proofVerificationStatus: VPVerificationStatus,
    var vcResults: List<VCResultWithCredentialStatus>
)

data class VCResult(
    val vc: String,
    val status: VerificationStatus
)

data class VCResultWithCredentialStatus(
    val vc: String,
    val status: VerificationStatus,
    val credentialStatus: List<CredentialStatusResult>
)

enum class VerificationStatus {
    SUCCESS,
    EXPIRED,
    REVOKED,
    INVALID
}

enum class VPVerificationStatus {
    VALID,
    EXPIRED,
    INVALID
}

enum class DataModel {
    DATA_MODEL_1_1,
    DATA_MODEL_2_0,
    UNSUPPORTED
}

data class ValidationStatus(
    val validationMessage: String,
    val validationErrorCode: String
)

data class CredentialStatusResult(
    val purpose: String,
    val status: Int,
    val valid: Boolean,
    val error: StatusCheckException?
)

data class CredentialVerificationSummary(
    val verificationResult: VerificationResult,
    val credentialStatus: List<CredentialStatusResult>
)