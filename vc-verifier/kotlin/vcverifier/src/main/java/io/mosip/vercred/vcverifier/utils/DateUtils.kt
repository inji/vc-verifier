package io.mosip.vercred.vcverifier.utils

import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_EXPIRATION_DATE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_ISSUANCE_DATE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_VALID_FROM_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_VALID_UNTIL_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXPIRATION_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_UNTIL
import io.mosip.vercred.vcverifier.exception.ValidationException
import org.json.JSONObject
import org.threeten.bp.Instant
import org.threeten.bp.LocalDateTime
import org.threeten.bp.OffsetDateTime
import org.threeten.bp.ZoneOffset
import org.threeten.bp.format.DateTimeFormatter
import java.util.Date
import java.util.logging.Logger

object DateUtils {

    private val logger = Logger.getLogger(DateUtils::class.java.name)

    private val formatterWithOffset: DateTimeFormatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME
    private val formatterLocal: DateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME

    fun isValidDate(dateString: String): Boolean {
        return parseDate(dateString) != null
    }

    fun parseDate(dateString: String): Date? {
        return try {
            val offsetDateTime = OffsetDateTime.parse(dateString, formatterWithOffset)
            Date(offsetDateTime.toInstant().toEpochMilli())
        } catch (e: Exception) {
            try {
                val localDateTime = LocalDateTime.parse(dateString, formatterLocal)
                Date(localDateTime.toInstant(ZoneOffset.UTC).toEpochMilli())
            } catch (_: Exception) {
                null
            }
        }
    }

    fun validateV1DateFields(vcJsonObject: JSONObject) {
        listOf(
            ISSUANCE_DATE to ERROR_ISSUANCE_DATE_INVALID,
            EXPIRATION_DATE to ERROR_EXPIRATION_DATE_INVALID
        ).map { (dateKey, errorMessage) ->
            if (vcJsonObject.has(dateKey) && !isValidDate(vcJsonObject[dateKey].toString())) {
                throw ValidationException(errorMessage, "${ERROR_CODE_INVALID}${dateKey.uppercase()}")
            }
        }


        val issuanceDate = vcJsonObject.optString(ISSUANCE_DATE) ?: ""

        if (isFutureDateWithTolerance(issuanceDate)) {
            throw ValidationException(ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE,
                ERROR_CODE_CURRENT_DATE_BEFORE_ISSUANCE_DATE
            )
        }

    }

    fun validateV2DateFields(vcJsonObject: JSONObject) {

        listOf(
            VALID_FROM to ERROR_VALID_FROM_INVALID,
            VALID_UNTIL to ERROR_VALID_UNTIL_INVALID
        ).map { (dateKey, errorMessage) ->
            if (vcJsonObject.has(dateKey) && !isValidDate(vcJsonObject[dateKey].toString())) {
                throw ValidationException(errorMessage,"${ERROR_CODE_INVALID}${dateKey.uppercase()}")
            }
        }

        if (vcJsonObject.has(VALID_FROM) && isFutureDateWithTolerance(
                vcJsonObject.optString(
                    VALID_FROM
                )
            )
        ) {
            throw ValidationException(ERROR_CURRENT_DATE_BEFORE_VALID_FROM, ERROR_CODE_CURRENT_DATE_BEFORE_VALID_FROM)
        }
    }

    fun isVCExpired(inputDate: String): Boolean {
        return inputDate.isNotEmpty() && !isFutureDateWithTolerance(inputDate)
    }

    fun isFutureDateWithTolerance(inputDateString: String, toleranceInMilliSeconds: Long = 3000): Boolean {
        val inputDate: Date? = try {
            parseDate(inputDateString)
        } catch (e: Exception) {
            logger.severe("Given date is not available in supported date formats")
            return false
        }
        if (inputDate == null) {
            logger.severe("Failed to parse the input date")
            return false
        }
        val currentTime = System.currentTimeMillis()
        val inputDateTime = inputDate.time

        val upperBound = currentTime + toleranceInMilliSeconds
        return inputDateTime > upperBound
    }

    fun formatEpochSecondsToIsoUtc(epochSeconds: Long): String {
        val odt = OffsetDateTime.ofInstant(Instant.ofEpochSecond(epochSeconds), ZoneOffset.UTC)
        return odt.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
    }

    /**
     * ISO 18013-5 tdate values in validityInfo must be full-date-times in UTC with no
     * fractional seconds, e.g. `2024-10-23T07:01:17Z`.
     */
    fun isIsoMsoDateTime(dateString: String): Boolean {
        return MSO_DATE_TIME_PATTERN.matches(dateString) && parseDate(dateString) != null
    }

    fun isIsoFullDate(dateString: String): Boolean {
        return FULL_DATE_PATTERN.matches(dateString)
    }

    private val MSO_DATE_TIME_PATTERN = Regex("""^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$""")
    private val FULL_DATE_PATTERN = Regex("""^\d{4}-\d{2}-\d{2}$""")

}