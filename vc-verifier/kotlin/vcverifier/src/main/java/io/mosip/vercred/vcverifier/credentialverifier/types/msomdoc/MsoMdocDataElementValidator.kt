package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.SimpleValueType
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MDL_ELEMENT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MDL_AGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MDL_ELEMENT_TEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MDL_ELEMENT_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_MDL_MANDATORY_ELEMENT
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils.getOrNull
import io.mosip.vercred.vcverifier.utils.DateUtils
import org.threeten.bp.LocalDate
import org.threeten.bp.Period
import org.threeten.bp.ZoneOffset
import java.io.ByteArrayInputStream
import java.math.BigInteger

/**
 * ISO/IEC 18013-5 Table 5 / 7.2.4 / 7.2.5 checks for namespace org.iso.18013.5.1.
 */
internal object MsoMdocDataElementValidator {

    private const val MAX_LATIN1_LENGTH = 150
    private val AGE_OVER_PATTERN = Regex("""^age_over_(\d{2})$""")

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

    fun validate(
        namespaces: IssuerSignedNamespaces,
        mso: Map,
        checkTypesAndStructure: Boolean,
        checkMandatoryPresence: Boolean,
    ) {
        val records = collectMdlRecords(namespaces)
        if (records.isEmpty()) {
            if (checkMandatoryPresence) {
                throw ValidationException(
                    ERROR_MESSAGE_MISSING_MDL_MANDATORY_ELEMENT,
                    ERROR_CODE_INVALID_MDL_ELEMENT
                )
            }
            return
        }

        // Issue #300 §3.4: mandatory fields apply to a full issued credential only
        // (all MSO digests for org.iso.18013.5.1 are present). Selective disclosure skips this.
        val enforceMandatory =
            checkMandatoryPresence && isFullMdlIssuedCredential(namespaces, mso)
        if (enforceMandatory) {
            val present = records.keys
            val missing = MANDATORY_ELEMENTS - present
            if (missing.isNotEmpty()) {
                throw ValidationException(
                    "$ERROR_MESSAGE_MISSING_MDL_MANDATORY_ELEMENT (${missing.sorted().joinToString()})",
                    ERROR_CODE_INVALID_MDL_ELEMENT
                )
            }
        }

        if (!checkTypesAndStructure) {
            return
        }

        records.forEach { (identifier, value) ->
            validateElementType(identifier, value)
        }

        validateAgeConsistency(records, mso)
    }

    /**
     * True when every digestID in the MSO for [MDL_NAMESPACE] appears in the received nameSpaces.
     * Empty MSO digests are treated as not-full so mandatory checks are not vacuously applied.
     */
    fun isFullMdlIssuedCredential(
        namespaces: IssuerSignedNamespaces,
        mso: Map,
    ): Boolean {
        val msoDigestIds = collectMsoMdlDigestIds(mso)
        if (msoDigestIds.isEmpty()) {
            return false
        }
        val receivedDigestIds = collectReceivedMdlDigestIds(namespaces)
        return receivedDigestIds.containsAll(msoDigestIds)
    }

    private fun collectMsoMdlDigestIds(mso: Map): Set<BigInteger> {
        val valueDigestsRoot = mso.getOrNull(VALUE_DIGESTS) as? Map ?: return emptySet()
        val byNamespace: Map =
            if (valueDigestsRoot.keys.contains(UnicodeString(NAME_SPACES))) {
                valueDigestsRoot[NAME_SPACES] as? Map ?: return emptySet()
            } else {
                valueDigestsRoot
            }
        val mdlDigests = byNamespace[UnicodeString(MDL_NAMESPACE)] as? Map ?: return emptySet()
        return mdlDigests.keys.mapNotNull { key ->
            (key as? UnsignedInteger)?.value
        }.toSet()
    }

    private fun collectReceivedMdlDigestIds(namespaces: IssuerSignedNamespaces): Set<BigInteger> {
        val result = linkedSetOf<BigInteger>()
        namespaces.keys.forEach { namespaceKey ->
            if ((namespaceKey as? UnicodeString)?.string != MDL_NAMESPACE) {
                return@forEach
            }
            val items = (namespaces[namespaceKey] as? Array)?.dataItems ?: return@forEach
            items.forEach { item ->
                if (item !is ByteString) return@forEach
                val decoded = CborDecoder(ByteArrayInputStream(item.bytes)).decode()[0] as? Map
                    ?: return@forEach
                val digestId = (decoded[DIGEST_ID] as? UnsignedInteger)?.value ?: return@forEach
                result.add(digestId)
            }
        }
        return result
    }

    private fun collectMdlRecords(namespaces: IssuerSignedNamespaces): kotlin.collections.Map<String, DataItem> {
        val result = linkedMapOf<String, DataItem>()
        namespaces.keys.forEach { namespaceKey ->
            if ((namespaceKey as? UnicodeString)?.string != MDL_NAMESPACE) {
                return@forEach
            }
            val items = (namespaces[namespaceKey] as Array).dataItems
            items.forEach { item ->
                if (item !is ByteString) return@forEach
                val decoded = CborDecoder(ByteArrayInputStream(item.bytes)).decode()[0] as? Map
                    ?: return@forEach
                val identifier = (decoded["elementIdentifier"] as? UnicodeString)?.string ?: return@forEach
                val value = decoded["elementValue"] ?: return@forEach
                result[identifier] = value
            }
        }
        return result
    }

    private fun validateElementType(identifier: String, value: DataItem) {
        when {
            identifier in LATIN1_TEXT_ELEMENTS -> requireLatin1Text(identifier, value)
            identifier == "issuing_country" || identifier == "nationality" ||
                identifier == "resident_country" || identifier == "issuing_jurisdiction" ||
                identifier == "un_distinguishing_sign" -> requireText(identifier, value)
            identifier == "birth_date" || identifier == "issue_date" || identifier == "expiry_date" ->
                requireFullDate(identifier, value)
            identifier == "portrait" || identifier.startsWith("biometric_template_") ||
                identifier == "signature_usual_mark" -> requireByteString(identifier, value)
            identifier == "driving_privileges" -> validateDrivingPrivileges(value)
            identifier == "age_in_years" || identifier == "sex" || identifier == "height" ||
                identifier == "weight" || identifier == "age_birth_year" -> requireUnsigned(identifier, value)
            AGE_OVER_PATTERN.matches(identifier) -> requireBoolean(identifier, value)
            identifier == "family_name_national_character" ||
                identifier == "given_name_national_character" -> requireText(identifier, value)
            // Unknown/domestic identifiers: type not enforced here.
        }
    }

    private fun validateDrivingPrivileges(value: DataItem) {
        if (value !is Array) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES,
                ERROR_CODE_INVALID_MDL_ELEMENT
            )
        }
        value.dataItems.forEach { entry ->
            if (entry !is Map) {
                throw ValidationException(
                    ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES,
                    ERROR_CODE_INVALID_MDL_ELEMENT
                )
            }
            val category = entry.getOrNull("vehicle_category_code")
            if (category !is UnicodeString || category.string.isEmpty()) {
                throw ValidationException(
                    ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES,
                    ERROR_CODE_INVALID_MDL_ELEMENT
                )
            }
            entry.getOrNull("issue_date")?.let { requireFullDate("driving_privileges.issue_date", it) }
            entry.getOrNull("expiry_date")?.let { requireFullDate("driving_privileges.expiry_date", it) }
            val codes = entry.getOrNull("codes")
            if (codes != null) {
                if (codes !is Array || codes.dataItems.isEmpty()) {
                    throw ValidationException(
                        ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES,
                        ERROR_CODE_INVALID_MDL_ELEMENT
                    )
                }
                codes.dataItems.forEach { codeItem ->
                    if (codeItem !is Map || codeItem.getOrNull("code") !is UnicodeString) {
                        throw ValidationException(
                            ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES,
                            ERROR_CODE_INVALID_MDL_ELEMENT
                        )
                    }
                }
            }
        }
    }

    private fun validateAgeConsistency(
        records: kotlin.collections.Map<String, DataItem>,
        mso: Map,
    ) {
        val birthDateValue = records["birth_date"] ?: return
        val birthDate = parseFullDate(birthDateValue) ?: return

        val validFromItem = (mso.getOrNull("validityInfo") as? Map)?.getOrNull("validFrom")
        val validFromDate = validFromItem?.let { DateUtils.parseDate(it.toString()) } ?: return
        val asOf = org.threeten.bp.Instant.ofEpochMilli(validFromDate.time)
            .atZone(ZoneOffset.UTC)
            .toLocalDate()
        val ageYears = Period.between(birthDate, asOf).years
        if (ageYears < 0) {
            throw ValidationException(ERROR_MESSAGE_INVALID_MDL_AGE, ERROR_CODE_INVALID_MDL_ELEMENT)
        }

        records["age_in_years"]?.let { ageItem ->
            val declared = ((ageItem as? co.nstant.`in`.cbor.model.Number)?.value as? BigInteger)
                ?.toInt()
                ?: throw ValidationException(
                    ERROR_MESSAGE_INVALID_MDL_ELEMENT_TYPE,
                    ERROR_CODE_INVALID_MDL_ELEMENT
                )
            if (declared != ageYears) {
                throw ValidationException(ERROR_MESSAGE_INVALID_MDL_AGE, ERROR_CODE_INVALID_MDL_ELEMENT)
            }
        }

        records.forEach { (identifier, value) ->
            val match = AGE_OVER_PATTERN.matchEntire(identifier) ?: return@forEach
            val threshold = match.groupValues[1].toInt()
            val isOver = when {
                value is SimpleValue && value.simpleValueType == SimpleValueType.TRUE -> true
                value is SimpleValue && value.simpleValueType == SimpleValueType.FALSE -> false
                else -> throw ValidationException(
                    ERROR_MESSAGE_INVALID_MDL_ELEMENT_TYPE,
                    ERROR_CODE_INVALID_MDL_ELEMENT
                )
            }
            val actuallyOver = ageYears >= threshold
            if (isOver != actuallyOver) {
                throw ValidationException(ERROR_MESSAGE_INVALID_MDL_AGE, ERROR_CODE_INVALID_MDL_ELEMENT)
            }
        }
    }

    private fun requireLatin1Text(identifier: String, value: DataItem) {
        val text = requireText(identifier, value)
        if (text.length > MAX_LATIN1_LENGTH || text.any { it.code > 0xFF }) {
            throw ValidationException(
                "$ERROR_MESSAGE_INVALID_MDL_ELEMENT_TEXT ($identifier)",
                ERROR_CODE_INVALID_MDL_ELEMENT
            )
        }
    }

    private fun requireText(identifier: String, value: DataItem): String {
        if (value !is UnicodeString) {
            throw ValidationException(
                "$ERROR_MESSAGE_INVALID_MDL_ELEMENT_TYPE ($identifier)",
                ERROR_CODE_INVALID_MDL_ELEMENT
            )
        }
        return value.string
    }

    private fun requireFullDate(identifier: String, value: DataItem) {
        if (parseFullDate(value) == null) {
            throw ValidationException(
                "$ERROR_MESSAGE_INVALID_MDL_ELEMENT_TYPE ($identifier)",
                ERROR_CODE_INVALID_MDL_ELEMENT
            )
        }
    }

    private fun parseFullDate(value: DataItem): LocalDate? {
        val text = when (value) {
            is UnicodeString -> value.string
            else -> value.toString()
        }
        if (!DateUtils.isIsoFullDate(text)) return null
        return try {
            LocalDate.parse(text)
        } catch (_: Exception) {
            null
        }
    }

    private fun requireByteString(identifier: String, value: DataItem) {
        if (value !is ByteString) {
            throw ValidationException(
                "$ERROR_MESSAGE_INVALID_MDL_ELEMENT_TYPE ($identifier)",
                ERROR_CODE_INVALID_MDL_ELEMENT
            )
        }
    }

    private fun requireUnsigned(identifier: String, value: DataItem) {
        if (value !is UnsignedInteger &&
            !(value is co.nstant.`in`.cbor.model.Number && value.value.signum() >= 0)
        ) {
            throw ValidationException(
                "$ERROR_MESSAGE_INVALID_MDL_ELEMENT_TYPE ($identifier)",
                ERROR_CODE_INVALID_MDL_ELEMENT
            )
        }
    }

    private fun requireBoolean(identifier: String, value: DataItem) {
        if (value !is SimpleValue ||
            (value.simpleValueType != SimpleValueType.TRUE &&
                value.simpleValueType != SimpleValueType.FALSE)
        ) {
            throw ValidationException(
                "$ERROR_MESSAGE_INVALID_MDL_ELEMENT_TYPE ($identifier)",
                ERROR_CODE_INVALID_MDL_ELEMENT
            )
        }
    }
}
