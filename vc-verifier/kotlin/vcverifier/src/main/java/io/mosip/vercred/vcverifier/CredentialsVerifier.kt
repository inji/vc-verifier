package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.constants.CredentialFormat.LDP_VC
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_CODE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_MESSAGE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.EXCEPTION_DURING_VERIFICATION
import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifierFactory
import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.data.CredentialVerificationSummary
import io.mosip.vercred.vcverifier.data.ValidationStatus
import io.mosip.vercred.vcverifier.data.VerificationResult
import java.util.logging.Logger


class CredentialsVerifier {
    private val logger = Logger.getLogger(CredentialsVerifier::class.java.name)
    private val credentialVerifierFactory = CredentialVerifierFactory()

    /**
     * @deprecated This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification
     * Please use verify(credentials: String, format: CredentialFormat) instead, which is designed for supporting different VC formats.
     * This method only supports LDP VC format
     */
    @Deprecated("This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification")
    fun verifyCredentials(credentials: String?): Boolean {
        if (credentials == null) {
            logger.severe("Error - Input credential is null")
            throw RuntimeException("Input credential is null")
        }
        val credentialVerifier = credentialVerifierFactory.get(LDP_VC)
        val isVerified = credentialVerifier.verify(credentials)

        if (!isVerified) {
            logger.warning("Credential verification failed")
            return false
        }
        return true
    }

    fun verify(credential: String, credentialFormat: CredentialFormat): VerificationResult {
        val credentialVerifier = credentialVerifierFactory.get(credentialFormat)
        val validationStatus = credentialVerifier.validate(credential)
        if (validationStatus.validationMessage.isNotEmpty() && !validationStatus.validationErrorCode.contentEquals(
                ERROR_CODE_VC_EXPIRED
            )
        ) {
            return VerificationResult(
                false,
                validationStatus.validationMessage,
                validationStatus.validationErrorCode
            )
        }
        return try {
            val verifySignatureStatus = credentialVerifier.verify(credential)
            if (verifySignatureStatus) {
                return VerificationResult(
                    true,
                    validationStatus.validationMessage,
                    validationStatus.validationErrorCode
                )
            }
            return VerificationResult(
                false,
                ERROR_MESSAGE_VERIFICATION_FAILED,
                ERROR_CODE_VERIFICATION_FAILED
            )

        } catch (e: Exception) {
            val errorCode = validationStatus.validationErrorCode.takeIf { !it.isNullOrEmpty() }
                ?: ERROR_CODE_VERIFICATION_FAILED
            VerificationResult(false, "$EXCEPTION_DURING_VERIFICATION${e.message}", errorCode)
        }
    }

    fun getCredentialStatus(
        credential: String,
        credentialFormat: CredentialFormat,
        statusPurposeList: List<String> = emptyList()
    ): List<CredentialStatusResult> {
        try {
            val credentialStatusArray =
                credentialVerifierFactory.get(credentialFormat)
                    .checkStatus(credential, statusPurposeList)
            return credentialStatusArray ?: emptyList()
        } catch (e: Exception) {
            logger.severe("Error occurred while checking credential status: ${e.message}")
            throw e
        }
    }

    fun verifyAndGetCredentialStatus(
        credential: String,
        credentialFormat: CredentialFormat,
        statusPurposeList: List<String> = emptyList()
    ): CredentialVerificationSummary {
        val verificationResult = verify(credential, credentialFormat)
        if (verificationResult.verificationStatus) {
            val statusResults = getCredentialStatus(credential, credentialFormat, statusPurposeList)
            return CredentialVerificationSummary(verificationResult, statusResults)
        }
        return CredentialVerificationSummary(verificationResult, emptyList())
    }
}