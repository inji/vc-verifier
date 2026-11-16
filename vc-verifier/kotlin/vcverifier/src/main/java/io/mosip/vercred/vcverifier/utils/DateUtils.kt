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
import org.threeten.bp.LocalDate
import org.threeten.bp.LocalDateTime
import org.threeten.bp.OffsetDateTime
import org.threeten.bp.ZoneOffset
import org.threeten.bp.format.DateTimeFormatter
import org.threeten.bp.format.DateTimeParseException
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
     *
     * Intentionally does not rely on [parseDate] alone: it falls back to ISO_LOCAL_DATE_TIME,
     * which accepts a date-time with no zone and assumes UTC. The regex is what blocks that.
     */
    fun isIsoMsoDateTime(dateString: String): Boolean {
        return MSO_DATE_TIME_PATTERN.matches(dateString) && parseDate(dateString) != null
    }

    fun isIsoFullDate(dateString: String): Boolean {
        return FULL_DATE_PATTERN.matches(dateString)
    }

    /** Parses an ISO full-date (`YYYY-MM-DD`), or returns null for any other shape or an impossible date. */
    fun parseFullDateOrNull(dateString: String): LocalDate? {
        if (!isIsoFullDate(dateString)) return null
        return try {
            LocalDate.parse(dateString)
        } catch (_: DateTimeParseException) {
            null
        }
    }

    /**
     * Parses an ISO 18013-5 date that may be either a full-date (`YYYY-MM-DD`) or a tdate
     * (`YYYY-MM-DDThh:mm:ssZ`, taken as its UTC date). Returns null for anything else.
     */
    fun parseFullDateOrTdateOrNull(dateString: String): LocalDate? {
        parseFullDateOrNull(dateString)?.let { return it }
        if (!isIsoMsoDateTime(dateString)) return null
        val date = parseDate(dateString) ?: return null
        return Instant.ofEpochMilli(date.time).atZone(ZoneOffset.UTC).toLocalDate()
    }

    private val MSO_DATE_TIME_PATTERN = Regex("""^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$""")
    private val FULL_DATE_PATTERN = Regex("""^\d{4}-\d{2}-\d{2}$""")

}