package io.mosip.vercred.vcverifier.credentialverifier.validator

import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALIDITY_INFO_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALID_FROM_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALID_UNTIL_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_SIGNED_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALID_FROM_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALID_UNTIL_MSO
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.extractMso
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.DateUtils
import io.mosip.vercred.vcverifier.utils.DateUtils.parseDate
import java.util.logging.Logger

class MsoMdocValidator {
    private val logger = Logger.getLogger(MsoMdocValidator::class.java.name)



    fun validate(credential: String): Boolean {
        try {
            val (_, issuerSigned) = MsoMdocVerifiableCredential().parse(credential)

            /**
            a) The elements in the ‘ValidityInfo’ structure are verified against the current time stamp
             */

            val validityInfo: Map = issuerSigned.issuerAuth.extractMso()["validityInfo"] as Map
            val validFrom: DataItem? = validityInfo["validFrom"]
            val validUntil: DataItem? = validityInfo["validUntil"]
            val signed: DataItem? = validityInfo["signed"]
            if (validUntil == null || validFrom == null || signed == null) {
                logger.severe("Invalid ValidityInfo in the credential's MSO")
                throw ValidationException(ERROR_MESSAGE_INVALID_DATE_MSO, ERROR_CODE_INVALID_DATE_MSO)
            }
            val isValidFromIsFutureDate =
                DateUtils.isFutureDateWithTolerance(validFrom.toString())
            val isValidUntilIsPastDate =
                !DateUtils.isFutureDateWithTolerance(validUntil.toString())
            val isInvalidSignedData = DateUtils.isFutureDateWithTolerance(signed.toString())

            if(isInvalidSignedData) {
                logger.severe("Error while doing validity verification - MSO was signed with invalid date")
                throw ValidationException(ERROR_MESSAGE_INVALID_SIGNED_MSO,ERROR_CODE_INVALID_VALIDITY_INFO_MSO)
            }

            val isValidUntilGreaterThanValidFrom: Boolean =
                parseDate(validUntil.toString())?.after(
                    parseDate(
                        validFrom.toString()
                    ) ?: return false
                ) ?: false

            if(isValidFromIsFutureDate){
                logger.severe("Error while doing validity verification - invalid validFrom in the MSO of the credential")
                throw ValidationException(ERROR_MESSAGE_INVALID_VALID_FROM_MSO, ERROR_CODE_INVALID_VALID_FROM_MSO)
            }

            if(isValidUntilIsPastDate){
                logger.severe("Error while doing validity verification - invalid validUntil in the MSO of the credential")
                throw ValidationException(ERROR_MESSAGE_INVALID_VALID_UNTIL_MSO, ERROR_CODE_INVALID_VALID_UNTIL_MSO)
            }

            if(!isValidUntilGreaterThanValidFrom){
                logger.severe("Error while doing validity verification - invalid validFrom / validUntil in the MSO of the credential")
                throw ValidationException(ERROR_MESSAGE_INVALID_DATE_MSO, ERROR_CODE_INVALID_DATE_MSO)
            }
            return true
        } catch (exception: Exception) {
            when(exception){
                is ValidationException -> throw exception

            }
            throw UnknownException("Error while doing validation of credential - ${exception.message}")
        }
    }
}

operator fun DataItem.get(name: String): DataItem? {
    check(this.majorType == MajorType.MAP)
    this as Map
    if (this.keys.contains(UnicodeString(name)))
        return this.get(UnicodeString(name))
    return null
}