package io.mosip.vercred.vcverifier.credentialverifier.validator

import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MSO_DATE_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MSO_VERSION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALIDITY_INFO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALIDITY_INFO_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALID_FROM_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALID_UNTIL_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_EXPECTED_UPDATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MSO_DIGEST_ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_VALID_FROM_BEFORE_SIGNED_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MSO_DATE_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MSO_VERSION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_SIGNED_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALID_FROM_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALID_UNTIL_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALUE_DIGESTS_STRUCTURE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_UNTIL
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DIGEST_ALGORITHM
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DIGEST_ID_MAX_EXCLUSIVE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MSO_VERSION_PATTERN
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.VERSION
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.requireSupportedDigestAlgorithm
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DOC_TYPE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.EXPECTED_UPDATE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MdocClock
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MdocDocTypes
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.decodeIssuerSignedItems
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerificationOptions
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.SIGNED
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.VALIDITY_INFO
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.VALUE_DIGESTS
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils.getOrNull
import io.mosip.vercred.vcverifier.utils.DateUtils
import io.mosip.vercred.vcverifier.utils.DateUtils.parseDate
import java.util.logging.Logger

private const val DATE_TAG = 0L

class MsoMdocValidator(
    private val options: MsoMdocVerificationOptions = MsoMdocVerificationOptions(),
) {
    private val logger = Logger.getLogger(MsoMdocValidator::class.java.name)


    fun validate(credential: String): Boolean {
        try {
            // The credential shape (A/B/C) only decides where IssuerSigned is found;
            // every MSO check below applies to all shapes.
            val (_, credentialData, _) = MsoMdocVerifiableCredential(options)
                .parse(credential, captureRawNameSpaces = false)

            val mso = credentialData.mso

            validateMsoStructure(mso)
            val isExpired = validateValidityInfo(mso)
            // docType-specific checks (e.g. mDL) run before the soft-expiry result, so an expired
            // credential still gets them.
            MdocDocTypes.validatorFor(mso)?.validate(
                decodeIssuerSignedItems(credentialData.issuerSigned.namespaces),
                mso,
                options,
            )
            if (isExpired) {
                throw ValidationException(ERROR_MESSAGE_VC_EXPIRED, ERROR_CODE_VC_EXPIRED)
            }
            return true
        } catch (exception: Exception) {
            if (exception is ValidationException) throw exception
            throw UnknownException("Error while doing validation of credential - ${exception.message}")
        }
    }

    private fun validateMsoStructure(mso: Map) {
        val mandatoryFields = listOf(
            VERSION,
            DIGEST_ALGORITHM,
            VALUE_DIGESTS,
            "deviceKeyInfo",
            DOC_TYPE,
            VALIDITY_INFO
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

        if (mso.getOrNull(VALIDITY_INFO) !is Map) {
            logger.severe("validityInfo in the credential's MSO is not a map/object as expected")
            throw ValidationException(
                "validityInfo is not available in MSO which is expected",
                ERROR_CODE_INVALID_MSO
            )
        }

        val version = (mso.getOrNull(VERSION) as? UnicodeString)?.string
        if (version == null || !MSO_VERSION_PATTERN.matches(version)) {
            logger.severe("MSO version major must be 1, found: $version")
            throw ValidationException(
                ERROR_MESSAGE_INVALID_MSO_VERSION,
                ERROR_CODE_INVALID_MSO_VERSION
            )
        }

        requireSupportedDigestAlgorithm(mso)

        validateValueDigestsLayout(mso.getOrNull(VALUE_DIGESTS))
    }

    /**
     * ISO 18013-5 ValueDigests = { + NameSpace (tstr) => DigestIDs }, DigestIDs = { + uint => bstr }.
     * A malformed layout is an MSO problem, so it must not surface later as a digest mismatch.
     */
    private fun validateValueDigestsLayout(valueDigests: DataItem?) {
        val isValid = valueDigests is Map && valueDigests.keys.all { namespace ->
            namespace is UnicodeString &&
                (valueDigests[namespace] as? Map)?.let { digestIds ->
                    digestIds.keys.all { digestId ->
                        digestId is UnsignedInteger && digestIds[digestId] is ByteString
                    }
                } == true
        }
        if (!isValid) {
            logger.severe("valueDigests in the credential's MSO does not follow the ISO 18013-5 layout")
            throw ValidationException(
                ERROR_MESSAGE_INVALID_VALUE_DIGESTS_STRUCTURE,
                ERROR_CODE_INVALID_MSO
            )
        }
        // Layout is valid here, so every key is a uint inside a map.
        val digestIdInRange = (valueDigests as Map).values.all { digestIds ->
            (digestIds as Map).keys.all { (it as UnsignedInteger).value < DIGEST_ID_MAX_EXCLUSIVE }
        }
        if (!digestIdInRange) {
            logger.severe("valueDigests in the credential's MSO has a digestID of 2^31 or above")
            throw ValidationException(ERROR_MESSAGE_INVALID_MSO_DIGEST_ID, ERROR_CODE_INVALID_MSO)
        }
    }

    /**
     * The elements in the ValidityInfo structure are verified against the current time stamp.
     * Returns true when the MSO has expired (validUntil in the past). Expiry is a soft failure,
     * reported by the caller after the remaining checks; every other problem throws here.
     */
    private fun validateValidityInfo(mso: Map): Boolean {

        val validityInfo: Map = mso.getOrNull(VALIDITY_INFO) as Map
        val validFrom: DataItem? = validityInfo.getOrNull(VALID_FROM)
        val validUntil: DataItem? = validityInfo.getOrNull(VALID_UNTIL)
        val signed: DataItem? = validityInfo.getOrNull(SIGNED)
        val expectedUpdate: DataItem? = validityInfo.getOrNull(EXPECTED_UPDATE)
        // signed, validFrom and validUntil are mandatory in every MSO, whatever the credential shape.
        if (validUntil == null || validFrom == null || signed == null) {
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
            VALID_FROM,
            ERROR_MESSAGE_INVALID_VALID_FROM_MSO,
            ERROR_CODE_INVALID_VALID_FROM_MSO,
            validateTag = true,
        )

        requireValidDate(
            validUntil,
            VALID_UNTIL,
            ERROR_MESSAGE_INVALID_VALID_UNTIL_MSO,
            ERROR_CODE_INVALID_VALID_UNTIL_MSO,
            validateTag = true,
        )
        requireValidDate(
            signed,
            SIGNED,
            ERROR_MESSAGE_INVALID_SIGNED_MSO,
            ERROR_CODE_INVALID_VALIDITY_INFO_MSO,
            validateTag = true,
        )
        if (expectedUpdate != null) {
            requireValidDate(
                expectedUpdate,
                EXPECTED_UPDATE,
                ERROR_MESSAGE_INVALID_EXPECTED_UPDATE_MSO,
                ERROR_CODE_INVALID_VALIDITY_INFO,
                validateTag = true,
            )
            requireIsoMsoDateFormat(expectedUpdate.toString(), EXPECTED_UPDATE)
        }

        requireIsoMsoDateFormat(validFromString, VALID_FROM)
        requireIsoMsoDateFormat(validUntilString, VALID_UNTIL)
        requireIsoMsoDateFormat(signedString, SIGNED)

        // requireValidDate above guarantees these parse.
        val validFromMillis = parseDate(validFromString)!!.time
        val validUntilMillis = parseDate(validUntilString)!!.time
        val signedMillis = parseDate(signedString)!!.time
        val now = options.currentTimeMillis()

        if (MdocClock.isAfterNow(validFromMillis, now)) {
            logger.severe("Error while doing validity verification - validFrom is in the future")
            throw ValidationException(
                ERROR_CURRENT_DATE_BEFORE_VALID_FROM,
                ERROR_CODE_CURRENT_DATE_BEFORE_VALID_FROM
            )
        }

        if (MdocClock.isAfterNow(signedMillis, now)) {
            logger.severe("Error while doing validity verification - MSO was signed with invalid date")
            throw ValidationException(
                ERROR_MESSAGE_INVALID_SIGNED_MSO,
                ERROR_CODE_INVALID_VALIDITY_INFO_MSO
            )
        }

        if (validFromMillis < signedMillis) {
            logger.severe("Error while doing validity verification - validFrom must not be before signed in the MSO of the credential")
            throw ValidationException(
                ERROR_MESSAGE_VALID_FROM_BEFORE_SIGNED_MSO,
                ERROR_CODE_INVALID_VALID_FROM_MSO
            )
        }

        // Ordering must be checked before soft-expiry so an inverted window fails hard
        // (ERR_INVALID_DATE_MSO) even when both dates are in the past.
        if (validUntilMillis <= validFromMillis) {
            logger.severe("Error while doing validity verification - invalid validFrom / validUntil in the MSO of the credential")
            throw ValidationException(ERROR_MESSAGE_INVALID_DATE_MSO, ERROR_CODE_INVALID_DATE_MSO)
        }

        // Expired only once validUntil is more than the tolerance in the past.
        val isExpired = MdocClock.isBeforeNow(validUntilMillis, now)
        if (isExpired) {
            logger.severe("Error while doing validity verification - MSO validUntil is in the past")
        }
        return isExpired
    }

    private fun requireIsoMsoDateFormat(dateString: String, fieldName: String) {
        if (!DateUtils.isIsoMsoDateTime(dateString)) {
            logger.severe("Invalid MSO date format for $fieldName: $dateString")
            throw ValidationException(
                "$ERROR_MESSAGE_INVALID_MSO_DATE_FORMAT ($fieldName)",
                ERROR_CODE_INVALID_MSO_DATE_FORMAT
            )
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
