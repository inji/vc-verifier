package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.SimpleValueType
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MDL_ELEMENT
import io.mosip.vercred.vcverifier.exception.ValidationException
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream

class MsoMdocDataElementValidatorTest {

    @Test
    fun `should reject non-Latin1 family_name when strict`() {
        val namespaces = namespacesOf(
            item(0, "family_name", UnicodeString("日本"))
        )
        val exception = assertThrows(ValidationException::class.java) {
            MsoMdocDataElementValidator.validate(
                namespaces = namespaces,
                mso = emptyMso(),
                checkTypesAndStructure = true,
                checkMandatoryPresence = false,
            )
        }
        assertEquals(ERROR_CODE_INVALID_MDL_ELEMENT, exception.errorCode)
    }

    @Test
    fun `should reject driving_privileges without vehicle_category_code`() {
        val privilege = CborMap().apply {
            put(UnicodeString("issue_date"), UnicodeString("2020-01-01"))
        }
        val namespaces = namespacesOf(
            item(0, "driving_privileges", CborArray().apply { add(privilege) })
        )
        val exception = assertThrows(ValidationException::class.java) {
            MsoMdocDataElementValidator.validate(
                namespaces = namespaces,
                mso = emptyMso(),
                checkTypesAndStructure = true,
                checkMandatoryPresence = false,
            )
        }
        assertEquals(ERROR_CODE_INVALID_MDL_ELEMENT, exception.errorCode)
    }

    @Test
    fun `should reject missing mandatory elements for full issued credential`() {
        val namespaces = namespacesOf(
            item(0, "family_name", UnicodeString("Doe"))
        )
        val exception = assertThrows(ValidationException::class.java) {
            MsoMdocDataElementValidator.validate(
                namespaces = namespaces,
                mso = msoWithDigests(0),
                checkTypesAndStructure = false,
                checkMandatoryPresence = true,
            )
        }
        assertEquals(ERROR_CODE_INVALID_MDL_ELEMENT, exception.errorCode)
    }

    @Test
    fun `should skip mandatory elements under selective disclosure`() {
        val namespaces = namespacesOf(
            item(0, "family_name", UnicodeString("Doe"))
        )
        // MSO still has digest 1 undisclosed → not a full issued credential (§3.4).
        assertDoesNotThrow {
            MsoMdocDataElementValidator.validate(
                namespaces = namespaces,
                mso = msoWithDigests(0, 1),
                checkTypesAndStructure = false,
                checkMandatoryPresence = true,
            )
        }
    }

    @Test
    fun `should reject age_over inconsistent with birth_date`() {
        val namespaces = namespacesOf(
            item(0, "birth_date", UnicodeString("2010-01-01")),
            item(1, "age_over_18", SimpleValue(SimpleValueType.TRUE)),
        )
        val mso = CborMap().apply {
            put(
                UnicodeString("validityInfo"),
                CborMap().apply {
                    put(UnicodeString("validFrom"), UnicodeString("2024-01-01T00:00:00Z"))
                }
            )
        }
        val exception = assertThrows(ValidationException::class.java) {
            MsoMdocDataElementValidator.validate(
                namespaces = namespaces,
                mso = mso,
                checkTypesAndStructure = true,
                checkMandatoryPresence = false,
            )
        }
        assertEquals(ERROR_CODE_INVALID_MDL_ELEMENT, exception.errorCode)
    }

    private fun emptyMso(): CborMap = CborMap()

    private fun msoWithDigests(vararg digestIds: Long): CborMap {
        val digestMap = CborMap().apply {
            digestIds.forEach { id ->
                put(UnsignedInteger(id), ByteString(ByteArray(32)))
            }
        }
        return CborMap().apply {
            put(
                UnicodeString(VALUE_DIGESTS),
                CborMap().apply {
                    put(UnicodeString(MDL_NAMESPACE), digestMap)
                }
            )
        }
    }

    private fun item(
        digestId: Long,
        identifier: String,
        value: co.nstant.`in`.cbor.model.DataItem,
    ): ByteString {
        val map = CborMap().apply {
            put(UnicodeString("digestID"), UnsignedInteger(digestId))
            put(UnicodeString("random"), ByteString(ByteArray(16)))
            put(UnicodeString("elementIdentifier"), UnicodeString(identifier))
            put(UnicodeString("elementValue"), value)
        }
        val bytes = ByteArrayOutputStream().also { CborEncoder(it).encode(map) }.toByteArray()
        return ByteString(bytes).apply { setTag(24) }
    }

    private fun namespacesOf(vararg items: ByteString): CborMap {
        return CborMap().apply {
            put(
                UnicodeString(MDL_NAMESPACE),
                CborArray().apply { items.forEach { add(it) } }
            )
        }
    }
}
