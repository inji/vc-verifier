package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.mdl

import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DecodedIssuerSignedItem
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.SIGNED
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.VALIDITY_INFO
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.VALUE_DIGESTS
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.SimpleValueType
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MDL_ELEMENT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUE_DATE_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MDL_AGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_MDL_MANDATORY_ELEMENT
import io.mosip.vercred.vcverifier.exception.ValidationException
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.junit.jupiter.params.provider.ValueSource
import java.math.BigInteger

class MdlValidatorTest {

    // ---- element types ----

    @ParameterizedTest(name = "{0} = {1}")
    @MethodSource("wrongTypes")
    fun `should reject an mDL element of the wrong type`(identifier: String, value: DataItem) {
        assertInvalid { validateStrict(identifier to value) }
    }

    @ParameterizedTest(name = "{0} = {1}")
    @MethodSource("correctTypes")
    fun `should accept an mDL element of the right type`(identifier: String, value: DataItem) {
        assertDoesNotThrow { validateStrict(identifier to value) }
    }

    @Test
    fun `should not check element types when checkElementTypes is false`() {
        // issue_date is left out: a text issue_date that is not a date is still reported by the
        // always-on issue_date check (see the issue_date tests).
        val elements = wrongTypes().map { it.get()[0] as String to it.get()[1] as DataItem }
            .filterNot { it.first == "issue_date" }
            .distinctBy { it.first }
        assertDoesNotThrow {
            MdlValidator.validate(
                items = itemsOf(*elements.toTypedArray()),
                mso = CborMap(),
                checkElementTypes = false,
            )
        }
    }

    @Test
    fun `should ignore elements of other namespaces`() {
        val item = DecodedIssuerSignedItem("org.example", BigInteger.ZERO, "portrait", UnicodeString("text"))
        assertDoesNotThrow {
            MdlValidator.validate(listOf(item), msoWithDigests(0), checkElementTypes = true)
        }
    }

    // ---- relaxed mode (mdocStrictProfile = false): only element types are skipped ----

    @Test
    fun `should still check driving_privileges structure when element types are relaxed`() {
        val camelCase = arrayOf(mapOf("vehicleCategoryCode" to UnicodeString("A")))
        assertInvalid { validateRelaxed("driving_privileges" to camelCase) }
    }

    @Test
    fun `should still check Latin-1 text when element types are relaxed`() {
        assertInvalid { validateRelaxed("family_name" to UnicodeString("日本")) }
        assertInvalid { validateRelaxed("family_name" to UnicodeString("a".repeat(151))) }
    }

    @Test
    fun `should still check age consistency when element types are relaxed`() {
        assertInvalid {
            validateRelaxed(
                "birth_date" to UnicodeString("2010-01-01"),
                "age_over_18" to TRUE,
                mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
            )
        }
    }

    @Test
    fun `should skip, not report, wrong-typed values in the always-on checks when relaxed`() {
        assertDoesNotThrow {
            validateRelaxed(
                "family_name" to ByteString(byteArrayOf(1)),
                "birth_date" to UnicodeString("2010-01-01"),
                "age_over_18" to UnicodeString("true"),
                "age_in_years" to UnicodeString("30"),
                "portrait" to UnicodeString("base64-portrait"),
                mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
            )
        }
    }

    // ---- driving_privileges structure ----

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidDrivingPrivileges")
    fun `should reject invalid driving_privileges`(@Suppress("UNUSED_PARAMETER") case: String, value: DataItem) {
        val exception = assertInvalid { validateStrict("driving_privileges" to value) }
        assertEquals(ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES, exception.message)
    }

    @Test
    fun `should accept a full valid driving_privileges entry`() {
        val entry = privilege(
            "issue_date" to UnicodeString("2020-01-01"),
            "expiry_date" to UnicodeString("2030-01-01"),
            "codes" to CborArray().apply {
                add(
                    mapOf(
                        "code" to UnicodeString("S01"),
                        "sign" to UnicodeString("<="),
                        "value" to UnicodeString("3500"),
                    )
                )
            },
        )
        assertDoesNotThrow { validateStrict("driving_privileges" to arrayOf(entry)) }
    }

    @Test
    fun `should accept an empty driving_privileges array`() {
        assertDoesNotThrow { validateStrict("driving_privileges" to CborArray()) }
    }

    // ---- Latin-1 text ----

    @ParameterizedTest
    @ValueSource(strings = ["Müller", "José", "O'Brien-Smith", "ÿ"])
    fun `should accept printable Latin-1 text`(text: String) {
        assertDoesNotThrow { validateStrict("family_name" to UnicodeString(text)) }
    }

    @Test
    fun `should accept text of exactly 150 characters`() {
        assertDoesNotThrow { validateStrict("family_name" to UnicodeString("a".repeat(150))) }
    }

    @ParameterizedTest
    @ValueSource(strings = ["日本", "Doe\n", "Do\u0000e", "Do\u007Fe", "Do\u0085e"])
    fun `should reject non-Latin-1 or control characters in family_name`(text: String) {
        assertInvalid { validateStrict("family_name" to UnicodeString(text)) }
    }

    @Test
    fun `should reject text of 151 characters`() {
        assertInvalid { validateStrict("family_name" to UnicodeString("a".repeat(151))) }
    }

    @Test
    fun `should apply the Latin-1 rule to other listed fields such as resident_address`() {
        assertInvalid { validateStrict("resident_address" to UnicodeString("1 Main St\u0000")) }
        assertInvalid { validateStrict("resident_address" to UnicodeString("x".repeat(151))) }
    }

    @Test
    fun `should reject control characters only in strict mode`() {
        val multiLineAddress = "resident_address" to UnicodeString("1 Main St\nSpringfield")
        assertDoesNotThrow { validateRelaxed(multiLineAddress) }
        assertInvalid { validateStrict(multiLineAddress) }
    }

    @Test
    fun `should reject non-Latin-1 text and text over 150 characters in both modes`() {
        listOf(
            "family_name" to UnicodeString("日本"),
            "family_name" to UnicodeString("a".repeat(151)),
        ).forEach { element ->
            assertInvalid { validateStrict(element) }
            assertInvalid { validateRelaxed(element) }
        }
    }

    @Test
    fun `should accept full-dates tagged 1004 and untagged full-dates in strict mode`() {
        listOf<(String) -> DataItem>(
            { UnicodeString(it).apply { setTag(1004) } },
            { UnicodeString(it) },
        ).forEach { fullDate ->
            assertDoesNotThrow {
                validateStrict(
                    "birth_date" to fullDate("1990-01-01"),
                    "issue_date" to fullDate("2030-01-01"),
                    "expiry_date" to fullDate("2035-01-01"),
                )
            }
        }
    }

    @Test
    fun `should allow full UTF-8 in national character names`() {
        assertDoesNotThrow { validateStrict("family_name_national_character" to UnicodeString("山田")) }
    }

    // ---- mandatory elements ----

    @Test
    fun `should reject missing mandatory elements for a fully disclosed mDL namespace`() {
        val exception = assertInvalid {
            MdlValidator.validate(
                items = itemsOf("family_name" to UnicodeString("Doe")),
                mso = msoWithDigests(0),
                checkElementTypes = false,
            )
        }
        // The missing identifiers are logged, not returned.
        assertEquals(ERROR_MESSAGE_MISSING_MDL_MANDATORY_ELEMENT, exception.message)
    }

    @Test
    fun `should skip mandatory elements under selective disclosure`() {
        // MSO still has digest 1 undisclosed, so the mDL namespace is not fully disclosed.
        assertDoesNotThrow {
            MdlValidator.validate(
                items = itemsOf("family_name" to UnicodeString("Doe")),
                mso = msoWithDigests(0, 1),
                checkElementTypes = false,
            )
        }
    }

    @Test
    fun `should allow an empty disclosure when the MSO has undisclosed mDL digests`() {
        assertDoesNotThrow {
            MdlValidator.validate(
                items = emptyList(),
                mso = msoWithDigests(0),
                checkElementTypes = false,
            )
        }
    }

    @Test
    fun `should reject an empty disclosure when the MSO has no mDL digests`() {
        assertInvalid {
            MdlValidator.validate(
                items = emptyList(),
                mso = CborMap(),
                checkElementTypes = false,
            )
        }
    }

    @Test
    fun `should allow all mandatory elements for a fully disclosed mDL namespace`() {
        val requiredElements: List<Pair<String, DataItem>> = listOf(
            "family_name" to UnicodeString("Doe"),
            "given_name" to UnicodeString("Jane"),
            "birth_date" to UnicodeString("1990-01-01"),
            "issue_date" to UnicodeString("2024-01-01"),
            "expiry_date" to UnicodeString("2030-01-01"),
            "issuing_country" to UnicodeString("IN"),
            "issuing_authority" to UnicodeString("Authority"),
            "document_number" to UnicodeString("123456"),
            "portrait" to ByteString(byteArrayOf(1)),
            "driving_privileges" to arrayOf(privilege()),
            "un_distinguishing_sign" to UnicodeString("IND"),
        )
        assertDoesNotThrow {
            MdlValidator.validate(
                items = itemsOf(*requiredElements.toTypedArray()),
                mso = msoWithDigests(*requiredElements.indices.map { it.toLong() }.toLongArray()),
                checkElementTypes = true,
            )
        }
    }

    // ---- age consistency ----

    @Test
    fun `should reject age_over inconsistent with birth_date`() {
        val exception = assertInvalid {
            validateStrict(
                "birth_date" to UnicodeString("2010-01-01"),
                "age_over_18" to TRUE,
                mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
            )
        }
        assertEquals(ERROR_MESSAGE_INVALID_MDL_AGE, exception.message)
    }

    @Test
    fun `should accept consistent age_over_18 true and age_over_65 false`() {
        assertDoesNotThrow {
            validateStrict(
                "birth_date" to UnicodeString("2000-01-01"),
                "age_over_18" to TRUE,
                "age_over_65" to FALSE,
                mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
            )
        }
    }

    @ParameterizedTest
    @ValueSource(longs = [23, 24])
    fun `should accept a matching age_in_years`(age: Long) {
        // birth_date 2000-01-01, validFrom 2024-01-01: 23 is the age one day before.
        assertDoesNotThrow { validateAgeInYears(age) }
    }

    @ParameterizedTest
    @ValueSource(longs = [22, 25, 26])
    fun `should reject an age_in_years outside the signed-validFrom window`(age: Long) {
        assertInvalid { validateAgeInYears(age) }
    }

    @Test
    fun `should not wrap an age_in_years above Int MAX_VALUE`() {
        // 2^32 + 24 would wrap to 24 with toInt().
        val huge = UnsignedInteger(BigInteger.ONE.shiftLeft(32).add(BigInteger.valueOf(24)))
        assertInvalid {
            validateStrict(
                "birth_date" to UnicodeString("2000-01-01"),
                "age_in_years" to huge,
                mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
            )
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("ageClaimsAroundBirthday")
    fun `should accept age claims computed at signed or at validFrom when the birthday falls between`(
        identifier: String,
        value: DataItem,
    ) {
        // Turns 18 on 2024-01-10: 17 at signed, 18 at validFrom.
        assertDoesNotThrow {
            validateStrict(
                "birth_date" to UnicodeString("2006-01-10"),
                identifier to value,
                mso = msoWithValidity(signed = "2024-01-05T00:00:00Z", validFrom = "2024-01-15T00:00:00Z"),
            )
        }
    }

    @Test
    fun `should still reject an age claim outside the window around a birthday`() {
        assertInvalid {
            validateStrict(
                "birth_date" to UnicodeString("2006-01-10"),
                "age_in_years" to UnsignedInteger(19),
                mso = msoWithValidity(signed = "2024-01-05T00:00:00Z", validFrom = "2024-01-15T00:00:00Z"),
            )
        }
    }

    @ParameterizedTest(name = "birth_date {0}, {1} = {2}")
    @MethodSource("ageClaimsWithinOneDayOfUtcDate")
    fun `should accept an age claim that holds one calendar day from the UTC date`(
        birthDate: String,
        identifier: String,
        value: DataItem,
    ) {
        assertDoesNotThrow { validateAgeAtEveningUtc(birthDate, identifier to value) }
    }

    @ParameterizedTest(name = "birth_date {0}, {1} = {2}")
    @MethodSource("ageClaimsTwoDaysFromUtcDate")
    fun `should reject an age claim that holds only two or more days from the UTC date`(
        birthDate: String,
        identifier: String,
        value: DataItem,
    ) {
        assertInvalid { validateAgeAtEveningUtc(birthDate, identifier to value) }
    }

    @Test
    fun `should reject a birth_date after validFrom`() {
        assertInvalid {
            validateStrict(
                "birth_date" to UnicodeString("2025-01-01"),
                mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
            )
        }
    }

    @Test
    fun `should not check age_over_NN without birth_date`() {
        assertDoesNotThrow {
            validateStrict(
                "age_over_18" to FALSE,
                "age_over_99" to TRUE,
                mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
            )
        }
    }

    // ---- issue_date vs validFrom ----

    @Test
    fun `should pass when issue_date is the same day as validFrom`() {
        assertDoesNotThrow { validateIssueDate("2025-06-01", validFrom = "2025-06-01T10:00:00Z") }
    }

    @Test
    fun `should pass when issue_date is the day before validFrom`() {
        assertDoesNotThrow { validateIssueDate("2025-05-31", validFrom = "2025-06-01T00:00:00Z") }
    }

    @Test
    fun `should pass when issue_date is the day after the UTC date of validFrom`() {
        // An issuer east of UTC writes its local date, already the next day.
        assertDoesNotThrow { validateIssueDate("2026-06-15", validFrom = "2026-06-14T20:30:00Z") }
    }

    @Test
    fun `should fail when issue_date is more than one day after the UTC date of validFrom`() {
        val exception = assertIssueDateInvalid { validateIssueDate("2026-06-16", validFrom = "2026-06-14T20:30:00Z") }
        assertEquals(ERROR_MESSAGE_INVALID_ISSUE_DATE, exception.errorMessage)
    }

    @Test
    fun `should skip the issue_date check when issue_date is not disclosed`() {
        assertDoesNotThrow {
            validateRelaxed("family_name" to UnicodeString("Doe"), mso = msoWithValidity("2025-06-01T00:00:00Z"))
        }
    }

    @Test
    fun `should accept a tdate issue_date by its UTC date`() {
        assertDoesNotThrow { validateIssueDate("2025-06-01T23:00:00Z", validFrom = "2025-06-01T00:00:00Z") }
    }

    @Test
    fun `should pass a tdate issue_date on the day after the UTC date of validFrom`() {
        assertDoesNotThrow { validateIssueDate("2026-06-15T01:00:00Z", validFrom = "2026-06-14T20:30:00Z") }
    }

    @Test
    fun `should fail a tdate issue_date more than one day after the UTC date of validFrom`() {
        assertIssueDateInvalid { validateIssueDate("2026-06-16T00:00:00Z", validFrom = "2026-06-14T20:30:00Z") }
    }

    @ParameterizedTest
    @ValueSource(strings = ["2024-13-45", "2024-02-30", "2025-06-01T25:00:00Z", "01/06/2025"])
    fun `should fail an issue_date that is not a valid full-date or tdate`(issueDate: String) {
        // Relaxed mode, so the issue_date check reports it rather than the element type check.
        val exception = assertIssueDateInvalid { validateIssueDate(issueDate, validFrom = "2025-06-01T00:00:00Z") }
        assertEquals(ERROR_MESSAGE_INVALID_ISSUE_DATE_FORMAT, exception.errorMessage)
    }

    // ---- helpers ----

    private fun validateAgeInYears(age: Long) = validateStrict(
        "birth_date" to UnicodeString("2000-01-01"),
        "age_in_years" to UnsignedInteger(age),
        mso = msoWithValidity(validFrom = "2024-01-01T00:00:00Z"),
    )

    /** signed = validFrom = 2026-06-14T20:30:00Z, already 2026-06-15 east of UTC. */
    private fun validateAgeAtEveningUtc(birthDate: String, claim: Pair<String, DataItem>) = validateStrict(
        "birth_date" to UnicodeString(birthDate),
        claim,
        mso = msoWithValidity(validFrom = "2026-06-14T20:30:00Z"),
    )

    private fun validateStrict(vararg elements: Pair<String, DataItem>, mso: CborMap = DEFAULT_MSO) =
        MdlValidator.validate(
            items = itemsOf(*elements),
            mso = mso,
            checkElementTypes = true,
        )

    private fun validateRelaxed(vararg elements: Pair<String, DataItem>, mso: CborMap = DEFAULT_MSO) =
        MdlValidator.validate(items = itemsOf(*elements), mso = mso, checkElementTypes = false)

    private fun validateIssueDate(issueDate: String, validFrom: String) =
        validateRelaxed("issue_date" to UnicodeString(issueDate), mso = msoWithValidity(validFrom))

    private fun assertIssueDateInvalid(block: () -> Unit): ValidationException {
        val exception = assertThrows(ValidationException::class.java) { block() }
        assertEquals(ERROR_CODE_INVALID_ISSUE_DATE, exception.errorCode)
        return exception
    }

    private fun assertInvalid(block: () -> Unit): ValidationException {
        val exception = assertThrows(ValidationException::class.java) { block() }
        assertEquals(ERROR_CODE_INVALID_MDL_ELEMENT, exception.errorCode)
        return exception
    }

    private fun itemsOf(vararg elements: Pair<String, DataItem>): List<DecodedIssuerSignedItem> =
        elements.mapIndexed { index, (identifier, value) ->
            DecodedIssuerSignedItem(MDL_NAMESPACE, BigInteger.valueOf(index.toLong()), identifier, value)
        }

    private fun msoWithDigests(vararg digestIds: Long): CborMap {
        val digestMap = CborMap().apply {
            digestIds.forEach { id -> put(UnsignedInteger(id), ByteString(ByteArray(32))) }
        }
        return msoWithValidity(validFrom = DEFAULT_VALID_FROM).apply {
            put(UnicodeString(VALUE_DIGESTS), CborMap().apply { put(UnicodeString(MDL_NAMESPACE), digestMap) })
        }
    }

    private fun msoWithValidity(validFrom: String, signed: String = validFrom): CborMap =
        CborMap().apply {
            put(
                UnicodeString(VALIDITY_INFO),
                CborMap().apply {
                    put(UnicodeString(SIGNED), UnicodeString(signed).apply { setTag(0) })
                    put(UnicodeString("validFrom"), UnicodeString(validFrom).apply { setTag(0) })
                }
            )
        }

    companion object {
        private const val DEFAULT_VALID_FROM = "2030-01-01T00:00:00Z"
        private val DEFAULT_MSO: CborMap
            get() = CborMap().apply {
                put(
                    UnicodeString(VALIDITY_INFO),
                    CborMap().apply {
                        put(UnicodeString(SIGNED), UnicodeString(DEFAULT_VALID_FROM).apply { setTag(0) })
                        put(UnicodeString("validFrom"), UnicodeString(DEFAULT_VALID_FROM).apply { setTag(0) })
                    }
                )
            }
        private val TRUE = SimpleValue(SimpleValueType.TRUE)
        private val FALSE = SimpleValue(SimpleValueType.FALSE)

        private fun mapOf(vararg entries: Pair<String, DataItem>): CborMap =
            CborMap().apply { entries.forEach { (key, value) -> put(UnicodeString(key), value) } }

        private fun arrayOf(vararg items: DataItem): CborArray =
            CborArray().apply { items.forEach { add(it) } }

        private fun privilege(vararg extra: Pair<String, DataItem>): CborMap =
            mapOf("vehicle_category_code" to UnicodeString("A"), *extra)

        private fun args(vararg values: Any) = Arguments.of(*values)

        @JvmStatic
        fun wrongTypes() = listOf(
            args("portrait", UnicodeString("base64-portrait")), // Certify issues portrait as text
            args("birth_date", UnicodeString("15/06/1990")),
            args("birth_date", UnicodeString("2024-02-30")),
            args("birth_date", UnicodeString("1990-06-15T00:00:00Z")),
            args("issue_date", UnicodeString("2024-02-30")),
            args("issue_date", UnsignedInteger(20240101)),
            args("expiry_date", UnicodeString("2030-01-01T00:00:00.000Z")),
            args("issuing_country", UnsignedInteger(356)),
            args("issuing_country", UnicodeString("India")),
            args("issuing_country", UnicodeString("in")),
            args("nationality", UnicodeString("IND")),
            args("un_distinguishing_sign", UnicodeString("INDIA")),
            args("un_distinguishing_sign", UnicodeString("")),
            args("issuing_jurisdiction", UnsignedInteger(1)),
            args("height", NegativeInteger(-1)),
            args("age_in_years", UnicodeString("30")),
            args("age_over_18", UnicodeString("true")),
            args("biometric_template_face", UnicodeString("template")),
            args("signature_usual_mark", UnicodeString("mark")),
            args("family_name", ByteString(byteArrayOf(1))),
        )

        @JvmStatic
        fun correctTypes() = listOf(
            args("portrait", ByteString(byteArrayOf(1, 2, 3))),
            args("birth_date", UnicodeString("1990-06-15")),
            args("issue_date", UnicodeString("2024-01-01")),
            args("issue_date", UnicodeString("2024-01-01T00:00:00Z")),
            args("expiry_date", UnicodeString("2030-01-01T00:00:00Z")),
            args("issuing_country", UnicodeString("IN")),
            args("resident_country", UnicodeString("DE")),
            args("un_distinguishing_sign", UnicodeString("IND")),
            args("un_distinguishing_sign", UnicodeString("D")),
            args("issuing_jurisdiction", UnicodeString("IN-KA")),
            args("height", UnsignedInteger(180)),
            args("age_over_18", TRUE),
            args("biometric_template_face", ByteString(byteArrayOf(1))),
            args("family_name", UnicodeString("Doe")),
            args("some_domestic_element", UnsignedInteger(1)),
        )

        @JvmStatic
        fun invalidDrivingPrivileges() = listOf(
            args("camelCase vehicleCategoryCode", arrayOf(mapOf("vehicleCategoryCode" to UnicodeString("A")))),
            args("a map instead of an array", privilege()),
            args("an entry that is not a map", arrayOf(UnicodeString("A"))),
            args("empty vehicle_category_code", arrayOf(mapOf("vehicle_category_code" to UnicodeString("")))),
            args("numeric vehicle_category_code", arrayOf(mapOf("vehicle_category_code" to UnsignedInteger(1)))),
            args("impossible issue_date", arrayOf(privilege("issue_date" to UnicodeString("2023-13-01")))),
            args("tdate issue_date", arrayOf(privilege("issue_date" to UnicodeString("2023-01-01T00:00:00Z")))),
            args("tdate expiry_date", arrayOf(privilege("expiry_date" to UnicodeString("2030-01-01T00:00:00Z")))),
            args("empty codes", arrayOf(privilege("codes" to CborArray()))),
            args("codes as a map", arrayOf(privilege("codes" to mapOf("code" to UnicodeString("S01"))))),
            args("code entry without code", arrayOf(privilege("codes" to arrayOf(mapOf("sign" to UnicodeString("=")))))),
            args(
                "numeric sign",
                arrayOf(privilege("codes" to arrayOf(mapOf("code" to UnicodeString("S01"), "sign" to UnsignedInteger(1))))),
            ),
            args(
                "numeric value",
                arrayOf(privilege("codes" to arrayOf(mapOf("code" to UnicodeString("S01"), "value" to UnsignedInteger(5))))),
            ),
        )

        /** Each claim is wrong on the UTC date 2026-06-14 but right one day before or after it. */
        @JvmStatic
        fun ageClaimsWithinOneDayOfUtcDate() = listOf(
            // Turns 18 on 2026-06-15 (the issuer's local date).
            args("2008-06-15", "age_over_18", TRUE),
            args("2008-06-15", "age_in_years", UnsignedInteger(18)),
            // Turned 18 on 2026-06-14 (UTC); the issuer's local date was still 2026-06-13.
            args("2008-06-14", "age_over_18", FALSE),
            args("2008-06-14", "age_in_years", UnsignedInteger(17)),
        )

        @JvmStatic
        fun ageClaimsTwoDaysFromUtcDate() = listOf(
            args("2008-06-16", "age_over_18", TRUE),
            args("2008-06-16", "age_in_years", UnsignedInteger(18)),
            args("2008-06-13", "age_over_18", FALSE),
            args("2008-06-13", "age_in_years", UnsignedInteger(17)),
        )

        @JvmStatic
        fun ageClaimsAroundBirthday() = listOf(
            args("age_over_18", TRUE),
            args("age_over_18", FALSE),
            args("age_in_years", UnsignedInteger(17)),
            args("age_in_years", UnsignedInteger(18)),
        )
    }
}
