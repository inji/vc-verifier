package io.mosip.vercred.vcverifier.credentialverifier.validator

import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALIDITY_INFO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALIDITY_INFO_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALID_FROM_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALID_UNTIL_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_EXPECTED_UPDATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_SIGNED_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALID_FROM_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALID_UNTIL_MSO
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils.getOrNull
import io.mosip.vercred.vcverifier.utils.DateUtils
import io.mosip.vercred.vcverifier.utils.DateUtils.parseDate
import java.util.logging.Logger

private const val DATE_TAG = 0L

class MsoMdocValidator {
    private val logger = Logger.getLogger(MsoMdocValidator::class.java.name)


    fun validate(credential: String): Boolean {
        try {
            val (_, credentialData, isLatest) = MsoMdocVerifiableCredential().parse(credential)

            val mso = credentialData.mso

            validateMsoStructure(mso)
            validateValidityInfo(mso, isLatest)
            return true
        } catch (exception: Exception) {
            if (exception is ValidationException) throw exception
            throw UnknownException("Error while doing validation of credential - ${exception.message}")
        }
    }

    private fun validateMsoStructure(mso: Map) {
        val mandatoryFields = listOf(
            "version",
            "digestAlgorithm",
            "valueDigests",
            "deviceKeyInfo",
            "docType",
            "validityInfo"
        )
        mandatoryFields.forEach { mandatoryField ->
            if (mso.getOrNull(mandatoryField) == null) {
                logger.severe("Mandatory field '$mandatoryField' is missing in the credential's MSO")
                throw ValidationException(
                    "$mandatoryField is not available in MSO which is expected",
                    ERROR_CODE_INVALID_MSO
                )
            }
        }

        if (mso.getOrNull("validityInfo") !is Map) {
            logger.severe("validityInfo in the credential's MSO is not a map/object as expected")
            throw ValidationException(
                "validityInfo is not available in MSO which is expected",
                ERROR_CODE_INVALID_MSO
            )
        }
    }

    private fun validateValidityInfo(mso: Map, isLatest: Boolean) {
        /**
        a) The elements in the ‘ValidityInfo’ structure are verified against the current time stamp
         */

        val validityInfo: Map = mso.getOrNull("validityInfo") as Map
        val validFrom: DataItem? = validityInfo.getOrNull("validFrom")
        val validUntil: DataItem? = validityInfo.getOrNull("validUntil")
        val signed: DataItem? = validityInfo.getOrNull("signed")
        val expectedUpdate: DataItem? = validityInfo.getOrNull("expectedUpdate")
        if (validUntil == null || validFrom == null || (isLatest && signed == null)) {
            logger.severe("Invalid ValidityInfo in the credential's MSO")
            throw ValidationException(
                "Invalid validityInfo - mandatory validityInfo values are not present",
                ERROR_CODE_INVALID_DATE_MSO
            )
        }

        val validFromString = validFrom.toString()
        val validUntilString = validUntil.toString()
        val signedString = signed.toString()
        requireValidDate(
            validFrom,
            "validFrom",
            ERROR_MESSAGE_INVALID_VALID_FROM_MSO,
            ERROR_CODE_INVALID_VALID_FROM_MSO,
            isLatest,
        )

        requireValidDate(
            validUntil,
            "validUntil",
            ERROR_MESSAGE_INVALID_VALID_UNTIL_MSO,
            ERROR_CODE_INVALID_VALID_UNTIL_MSO,
            isLatest,
        )
        if (isLatest) {
            requireValidDate(
                signed,
                "signed",
                ERROR_MESSAGE_INVALID_SIGNED_MSO,
                ERROR_CODE_INVALID_VALIDITY_INFO_MSO,
                true,
            )
        }
        if (expectedUpdate != null) {
            requireValidDate(
                expectedUpdate,
                "expectedUpdate",
                ERROR_MESSAGE_INVALID_EXPECTED_UPDATE_MSO,
                ERROR_CODE_INVALID_VALIDITY_INFO,
                validateTag = true,
            )
        }

        val isValidUntilIsPastDate =
            !DateUtils.isFutureDateWithTolerance(validUntilString)
        val isInvalidSignedData = isLatest && DateUtils.isFutureDateWithTolerance(signedString)

        if (isInvalidSignedData) {
            logger.severe("Error while doing validity verification - MSO was signed with invalid date")
            throw ValidationException(
                ERROR_MESSAGE_INVALID_SIGNED_MSO,
                ERROR_CODE_INVALID_VALIDITY_INFO_MSO
            )
        }

        val isValidUntilGreaterThanValidFrom: Boolean =
            parseDate(validUntilString)?.after(parseDate(validFromString)) ?: false

        val isValidFromBeforeSigned: Boolean =
            isLatest && (parseDate(validFromString)?.before(parseDate(signedString)) ?: false)

        if (isValidFromBeforeSigned) {
            logger.severe("Error while doing validity verification - validFrom must not be before signed in the MSO of the credential")
            throw ValidationException(
                ERROR_MESSAGE_INVALID_VALID_FROM_MSO,
                ERROR_CODE_INVALID_VALID_FROM_MSO
            )
        }

        if (isValidUntilIsPastDate) {
            logger.severe("Error while doing validity verification - invalid validUntil in the MSO of the credential")
            throw ValidationException(
                ERROR_MESSAGE_INVALID_VALID_UNTIL_MSO,
                ERROR_CODE_INVALID_VALID_UNTIL_MSO
            )
        }

        if (!isValidUntilGreaterThanValidFrom) {
            logger.severe("Error while doing validity verification - invalid validFrom / validUntil in the MSO of the credential")
            throw ValidationException(ERROR_MESSAGE_INVALID_DATE_MSO, ERROR_CODE_INVALID_DATE_MSO)
        }
    }

    private fun requireValidDate(
        date: DataItem?,
        fieldName: String,
        errorMessage: String,
        errorCode: String,
        validateTag: Boolean,
    ) {
        if (validateTag && date?.tag?.value != DATE_TAG) {
            logger.severe("Error while doing validity verification - $fieldName is not in date format")
            throw ValidationException(
                "Invalid validityInfo - $fieldName is not in date format",
                ERROR_CODE_INVALID_VALIDITY_INFO
            )
        }
        if (parseDate(date.toString()) == null) {
            logger.severe("Error while doing validity verification - invalid $fieldName in the MSO of the credential")
            throw ValidationException(errorMessage, errorCode)
        }
    }
}

