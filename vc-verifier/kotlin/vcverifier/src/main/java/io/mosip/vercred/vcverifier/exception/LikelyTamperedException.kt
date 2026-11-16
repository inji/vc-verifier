package io.mosip.vercred.vcverifier.exception

import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_LIKELY_TAMPERED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_LIKELY_TAMPERED

/**
 * Thrown when received credential data does not match what the issuer signed
 * (e.g. a digest mismatch), as opposed to a structural / validation problem.
 */
class LikelyTamperedException(
    val errorMessage: String = ERROR_MESSAGE_LIKELY_TAMPERED,
    val errorCode: String = ERROR_CODE_LIKELY_TAMPERED,
) : BaseUncheckedException(errorMessage)
