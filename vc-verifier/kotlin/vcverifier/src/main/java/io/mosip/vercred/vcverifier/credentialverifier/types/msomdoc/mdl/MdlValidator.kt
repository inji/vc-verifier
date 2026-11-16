package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.mdl

import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.SimpleValueType
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MDL_ELEMENT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALID_FROM_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUE_DATE_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MDL_AGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MDL_ELEMENT_TEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MDL_ELEMENT_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALID_FROM_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_MDL_MANDATORY_ELEMENT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_FROM
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DecodedIssuerSignedItem
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MdocDocTypeValidator
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerificationOptions
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.SIGNED
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.VALIDITY_INFO
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.VALUE_DIGESTS
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils.getOrNull
import io.mosip.vercred.vcverifier.utils.DateUtils
import org.threeten.bp.Instant
import org.threeten.bp.LocalDate
import org.threeten.bp.Period
import org.threeten.bp.ZoneOffset
import java.math.BigInteger
import java.util.logging.Logger

/**
 * mDL checks that run during validation, before the signature: ISO/IEC 18013-5 Table 5 / 7.2.4 /
 * 7.2.5 checks for the elements of namespace org.iso.18013.5.1, and issue_date vs validFrom.
 *
 * Runs only for docType org.iso.18013.5.1.mDL (chosen by MdocDocTypes).
 *
 * The strict flag relaxes only the element type checks. driving_privileges structure, Latin-1 text,
 * mandatory elements, age consistency and issue_date always run; in relaxed mode a value of the
 * wrong type is skipped by them rather than reported, since reporting it is the type check's job.
 */
internal object MdlValidator : MdocDocTypeValidator {

    private val logger = Logger.getLogger(MdlValidator::class.java.name)

    private const val MAX_LATIN1_LENGTH = 150
    private val AGE_OVER_PATTERN = Regex("""^age_over_(\d{2})$""")
    private val COUNTRY_CODE_PATTERN = Regex("""^[A-Z]{2}$""")
    private val UN_DISTINGUISHING_SIGN_PATTERN = Regex("""^[A-Z]{1,3}$""")
    private const val BIOMETRIC_TEMPLATE_PREFIX = "biometric_template_"

    private val MANDATORY_ELEMENTS = setOf(
        "family_name",
        "given_name",
        "birth_date",
        "issue_date",
        "expiry_date",
        "issuing_country",
        "issuing_authority",
        "document_number",
        "portrait",
        "driving_privileges",
        "un_distinguishing_sign",
    )

    // family_name_national_character / given_name_national_character are deliberately not here:
    // Table 5 allows full UTF-8 for them (see TEXT_ELEMENTS).
    private val LATIN1_TEXT_ELEMENTS = setOf(
        "family_name",
        "given_name",
        "issuing_authority",
        "document_number",
        "administrative_number",
        "birth_place",
        "resident_address",
        "resident_city",
        "resident_state",
        "resident_postal_code",
    )

    /** Any tstr. */
    private val TEXT_ELEMENTS = setOf(
        "issuing_jurisdiction",
        "family_name_national_character",
        "given_name_national_character",
    )

    /** ISO 3166-1 alpha-2 codes. */
    private val COUNTRY_CODE_ELEMENTS = setOf(
        "issuing_country",
        "nationality",
        "resident_country",
    )

    private val FULL_DATE_ELEMENTS = setOf("birth_date")

    /** Table 5 allows tdate or full-date for these. */
    private val FULL_DATE_OR_TDATE_ELEMENTS = setOf("issue_date", "expiry_date")

    /** Plus every identifier starting with [BIOMETRIC_TEMPLATE_PREFIX]. */
    private val BYTE_STRING_ELEMENTS = setOf("portrait", "signature_usual_mark")

    private val UNSIGNED_ELEMENTS = setOf(
        "age_in_years",
        "sex",
        "height",
        "weight",
        "age_birth_year",
    )

    /**
     * @param items every received IssuerSignedItem (see decodeIssuerSignedItems); only those in
     *   [MDL_NAMESPACE] are checked.
     *
     * Mandatory presence is enforced only when every MSO digest for [MDL_NAMESPACE] was received
     * (see [isMdlNamespaceFullyDisclosed]), so selective disclosure keeps working. The verifier cannot
     * tell "hidden by the holder" from "never issued": an mDL from a non-conformant issuer that left a
     * mandatory element out of the MSO entirely still passes whenever the holder hides at least one
     * other element. This is not full coverage of the mandatory-element rule.
     *
     * @param checkElementTypes enables the element type checks (strict mDL profile); every other
     *   check always runs.
     */
    fun validate(
        items: List<DecodedIssuerSignedItem>,
        mso: Map,
        checkElementTypes: Boolean,
    ) {
        val mdlItems = items.filter { it.namespace == MDL_NAMESPACE }

        // mandatory elements
        if (isMdlNamespaceFullyDisclosed(mdlItems, mso, emptyMeansFull = true)) {
            val missing = MANDATORY_ELEMENTS - mdlItems.map { it.elementIdentifier }.toSet()
            if (missing.isNotEmpty()) {
                logger.severe("Missing mandatory mDL elements: ${missing.sorted().joinToString()}")
                throw ValidationException(
                    ERROR_MESSAGE_MISSING_MDL_MANDATORY_ELEMENT,
                    ERROR_CODE_INVALID_MDL_ELEMENT
                )
            }
        }

        val records = mdlItems.associate { it.elementIdentifier to it.elementValue }
        records.forEach { (identifier, value) ->
            when {
                // driving_privileges structure
                identifier == "driving_privileges" -> validateDrivingPrivileges(value)
                // Latin-1 text; a non-text value is a type error, reported only when types are checked.
                identifier in LATIN1_TEXT_ELEMENTS ->
                    if (checkElementTypes || value is UnicodeString) requireLatin1Text(identifier, value)
                // element types
                checkElementTypes -> validateElementType(identifier, value)
            }
        }

        // age consistency
        validateAgeConsistency(records, mso)
        validateIssueDate(mso, mdlItems)
    }

    override fun validate(
        items: List<DecodedIssuerSignedItem>,
        mso: Map,
        options: MsoMdocVerificationOptions,
    ) = validate(items = items, mso = mso, checkElementTypes = options.strictMdlProfile)

    /**
     * issue_date must not be after the MSO validFrom (UTC date). ISO 18013-5 Table 5 allows
     * issue_date as full-date or tdate; a tdate is compared by its UTC date. The CBOR tag
     * (1004 / 0) is not checked here.
     */
    private fun validateIssueDate(mso: Map, items: List<DecodedIssuerSignedItem>) {
        val issueDateItem = items.firstOrNull { it.elementIdentifier == ISSUE_DATE }?.elementValue ?: return
        // A non-text value is a type error, reported by the element type check in strict mode.
        val issueDate = (issueDateItem as? UnicodeString)?.string ?: return
        // Also rejects impossible calendar dates (e.g. 2024-13-45).
        val issueLocalDate = DateUtils.parseFullDateOrTdateOrNull(issueDate)
            ?: throw ValidationException(
                ERROR_MESSAGE_INVALID_ISSUE_DATE_FORMAT,
                ERROR_CODE_INVALID_ISSUE_DATE
            )
        val validFromUtcDate = utcDateOf((mso.getOrNull(VALIDITY_INFO) as? Map)?.getOrNull(VALID_FROM))
            ?: throw ValidationException(
                ERROR_MESSAGE_INVALID_VALID_FROM_MSO,
                ERROR_CODE_INVALID_VALID_FROM_MSO
            )
        if (issueLocalDate.isAfter(validFromUtcDate)) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_ISSUE_DATE,
                ERROR_CODE_INVALID_ISSUE_DATE
            )
        }
    }

    /**
     * True when every digestID in the MSO for [MDL_NAMESPACE] appears among the received mDL items.
     * Only the mDL namespace is compared; other namespaces do not affect the result.
     * Empty MSO digests are treated as not-full so mandatory checks are not vacuously applied,
     * except that [emptyMeansFull] lets an empty disclosure against an MSO with no mDL digests fail.
     */
    fun isMdlNamespaceFullyDisclosed(
        items: List<DecodedIssuerSignedItem>,
        mso: Map,
        emptyMeansFull: Boolean = false,
    ): Boolean {
        val msoDigestIds = collectMsoMdlDigestIds(mso)
        val receivedDigestIds = items
            .filter { it.namespace == MDL_NAMESPACE }
            .map { it.digestId }
            .toSet()
        if (msoDigestIds.isEmpty()) {
            return emptyMeansFull && receivedDigestIds.isEmpty()
        }
        return receivedDigestIds.containsAll(msoDigestIds)
    }

    private fun collectMsoMdlDigestIds(mso: Map): Set<BigInteger> {
        val byNamespace = mso.getOrNull(VALUE_DIGESTS) as? Map ?: return emptySet()
        val mdlDigests = byNamespace[UnicodeString(MDL_NAMESPACE)] as? Map ?: return emptySet()
        return mdlDigests.keys.mapNotNull { key ->
            (key as? UnsignedInteger)?.value
        }.toSet()
    }

    /** Types of every element except driving_privileges and the Latin-1 text fields (checked above). */
    private fun validateElementType(identifier: String, value: DataItem) {
        when {
            identifier in TEXT_ELEMENTS -> requireText(identifier, value)
            identifier in COUNTRY_CODE_ELEMENTS -> requireMatching(identifier, value, COUNTRY_CODE_PATTERN)
            identifier == "un_distinguishing_sign" ->
                requireMatching(identifier, value, UN_DISTINGUISHING_SIGN_PATTERN)
            identifier in FULL_DATE_ELEMENTS -> requireFullDate(identifier, value)
            identifier in FULL_DATE_OR_TDATE_ELEMENTS -> requireFullDateOrTdate(identifier, value)
            identifier in BYTE_STRING_ELEMENTS || identifier.startsWith(BIOMETRIC_TEMPLATE_PREFIX) ->
                requireByteString(identifier, value)
            identifier in UNSIGNED_ELEMENTS -> requireUnsigned(identifier, value)
            AGE_OVER_PATTERN.matches(identifier) -> requireBoolean(identifier, value)
            // Unknown/domestic identifiers: type not enforced here.
        }
    }

    /** ISO 18013-5 7.2.4 DrivingPrivileges. Zero entries is allowed. */
    private fun validateDrivingPrivileges(value: DataItem) {
        if (value !is Array) {
            invalidDrivingPrivileges("driving_privileges is not an array")
        }
        value.dataItems.forEachIndexed { index, entry ->
            if (entry !is Map) {
                invalidDrivingPrivileges("entry $index is not a map")
            }
            val category = entry.getOrNull("vehicle_category_code")
            if (category !is UnicodeString || category.string.isEmpty()) {
                invalidDrivingPrivileges("missing or empty vehicle_category_code in entry $index")
            }
            listOf("issue_date", "expiry_date").forEach { dateKey ->
                val date = entry.getOrNull(dateKey) ?: return@forEach
                if (parseFullDate(date) == null) {
                    invalidDrivingPrivileges("$dateKey in entry $index is not a full-date")
                }
            }
            val codes = entry.getOrNull("codes") ?: return@forEachIndexed
            if (codes !is Array || codes.dataItems.isEmpty()) {
                invalidDrivingPrivileges("codes in entry $index is not a non-empty array")
            }
            codes.dataItems.forEachIndexed { codeIndex, codeItem ->
                if (codeItem !is Map || codeItem.getOrNull("code") !is UnicodeString) {
                    invalidDrivingPrivileges("codes[$codeIndex] in entry $index has no text code")
                }
                listOf("sign", "value").forEach { key ->
                    val item = codeItem.getOrNull(key)
                    if (item != null && item !is UnicodeString) {
                        invalidDrivingPrivileges("codes[$codeIndex].$key in entry $index is not text")
                    }
                }
            }
        }
    }

    /** Logs [detail] and throws; the returned message stays generic. */
    private fun invalidDrivingPrivileges(detail: String): Nothing {
        logger.severe("Invalid driving_privileges: $detail")
        throw ValidationException(ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES, ERROR_CODE_INVALID_MDL_ELEMENT)
    }

    /**
     * The issuer may compute ages at `signed` or at `validFrom` (which can be later), so a claim is
     * accepted if it holds at either end of that window:
     * - age_over_NN = true needs age at validFrom >= NN
     * - age_over_NN = false needs age at signed < NN
     * - age_in_years must lie between the age at signed and the age at validFrom
     * When `signed` is absent or equals `validFrom`, this is the plain check at validFrom.
     */
    private fun validateAgeConsistency(
        records: kotlin.collections.Map<String, DataItem>,
        mso: Map,
    ) {
        val birthDate = records["birth_date"]?.let { parseFullDate(it) } ?: return

        val validityInfo = mso.getOrNull(VALIDITY_INFO) as? Map ?: return
        val validFrom = utcDateOf(validityInfo.getOrNull(VALID_FROM)) ?: return
        val signed = utcDateOf(validityInfo.getOrNull(SIGNED)) ?: validFrom
        val earliest = if (signed.isBefore(validFrom)) signed else validFrom
        val latest = if (signed.isBefore(validFrom)) validFrom else signed

        if (birthDate.isAfter(latest)) {
            logger.severe("birth_date is after validFrom")
            throw ValidationException(ERROR_MESSAGE_INVALID_MDL_AGE, ERROR_CODE_INVALID_MDL_ELEMENT)
        }
        val minAge = ageAt(birthDate, earliest)
        val maxAge = ageAt(birthDate, latest)

        records["age_in_years"]?.let { ageItem ->
            // A wrong type is the type check's error (strict only); compared as BigInteger so large values cannot wrap.
            val declared = (ageItem as? UnsignedInteger)?.value ?: return@let
            if (declared < BigInteger.valueOf(minAge.toLong()) || declared > BigInteger.valueOf(maxAge.toLong())) {
                logger.severe("age_in_years is outside $minAge..$maxAge")
                throw ValidationException(ERROR_MESSAGE_INVALID_MDL_AGE, ERROR_CODE_INVALID_MDL_ELEMENT)
            }
        }

        records.forEach { (identifier, value) ->
            val match = AGE_OVER_PATTERN.matchEntire(identifier) ?: return@forEach
            val threshold = match.groupValues[1].toInt()
            val isOver = when ((value as? SimpleValue)?.simpleValueType) {
                SimpleValueType.TRUE -> true
                SimpleValueType.FALSE -> false
                else -> return@forEach // not a boolean: a type error, reported only in strict mode
            }
            val consistent = if (isOver) maxAge >= threshold else minAge < threshold
            if (!consistent) {
                logger.severe("$identifier is inconsistent with birth_date")
                throw ValidationException(ERROR_MESSAGE_INVALID_MDL_AGE, ERROR_CODE_INVALID_MDL_ELEMENT)
            }
        }
    }

    private fun ageAt(birthDate: LocalDate, date: LocalDate): Int =
        if (birthDate.isAfter(date)) -1 else Period.between(birthDate, date).years

    private fun utcDateOf(item: DataItem?): LocalDate? {
        val text = (item as? UnicodeString)?.string ?: return null
        val date = DateUtils.parseDate(text) ?: return null
        return Instant.ofEpochMilli(date.time).atZone(ZoneOffset.UTC).toLocalDate()
    }

    /** Printable Latin-1 only (0x20–0x7E, 0xA0–0xFF), at most 150 characters. */
    private fun requireLatin1Text(identifier: String, value: DataItem) {
        val text = requireText(identifier, value)
        if (text.length > MAX_LATIN1_LENGTH || !text.all { isPrintableLatin1(it) }) {
            throw ValidationException(
                "$ERROR_MESSAGE_INVALID_MDL_ELEMENT_TEXT ($identifier)",
                ERROR_CODE_INVALID_MDL_ELEMENT
            )
        }
    }

    private fun isPrintableLatin1(char: Char): Boolean =
        char.code in 0x20..0x7E || char.code in 0xA0..0xFF

    private fun requireText(identifier: String, value: DataItem): String {
        if (value !is UnicodeString) {
            invalidType(identifier)
        }
        return value.string
    }

    private fun requireMatching(identifier: String, value: DataItem, pattern: Regex) {
        if (!pattern.matches(requireText(identifier, value))) {
            invalidType(identifier)
        }
    }

    private fun requireFullDate(identifier: String, value: DataItem) {
        if (parseFullDate(value) == null) {
            invalidType(identifier)
        }
    }

    private fun requireFullDateOrTdate(identifier: String, value: DataItem) {
        val text = (value as? UnicodeString)?.string
        if (text == null || DateUtils.parseFullDateOrTdateOrNull(text) == null) {
            invalidType(identifier)
        }
    }

    /** Null for anything that is not a text full-date. */
    private fun parseFullDate(value: DataItem): LocalDate? {
        val text = (value as? UnicodeString)?.string ?: return null
        return DateUtils.parseFullDateOrNull(text)
    }

    private fun requireByteString(identifier: String, value: DataItem) {
        if (value !is ByteString) {
            invalidType(identifier)
        }
    }

    private fun requireUnsigned(identifier: String, value: DataItem) {
        if (value !is UnsignedInteger) {
            invalidType(identifier)
        }
    }

    private fun requireBoolean(identifier: String, value: DataItem) {
        if (value !is SimpleValue ||
            (value.simpleValueType != SimpleValueType.TRUE &&
                value.simpleValueType != SimpleValueType.FALSE)
        ) {
            invalidType(identifier)
        }
    }

    private fun invalidType(identifier: String): Nothing =
        throw ValidationException(
            "$ERROR_MESSAGE_INVALID_MDL_ELEMENT_TYPE ($identifier)",
            ERROR_CODE_INVALID_MDL_ELEMENT
        )
}
