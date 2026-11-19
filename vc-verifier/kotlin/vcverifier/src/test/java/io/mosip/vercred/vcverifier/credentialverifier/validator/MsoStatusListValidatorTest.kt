package io.mosip.vercred.vcverifier.credentialverifier.validator

import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_REFERENCE_MALFORMED
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MsoStatusListValidatorTest {

    private val validator = MsoStatusListValidator()

    @Test
    fun `missing status is absent`() {
        val result = validator.validate(Map())

        assertTrue(result is MsoStatusListValidationResult.Absent)
    }

    @Test
    fun `status without status_list is absent and ignores identifier_list`() {
        val mso = Map().apply {
            put(
                UnicodeString("status"),
                Map().apply {
                    put(UnicodeString("identifier_list"), Map())
                    put(UnicodeString("identifierList"), UnicodeString("ignored"))
                }
            )
        }

        assertTrue(validator.validate(mso) is MsoStatusListValidationResult.Absent)
    }

    @Test
    fun `reads uri and idx from status_list`() {
        val result = validator.validate(msoWithStatusList("https://example.com/statuslists/1", 7L))

        val found = result as MsoStatusListValidationResult.Found
        assertEquals("https://example.com/statuslists/1", found.pointer.uri)
        assertEquals(7L, found.pointer.idx)
    }

    @Test
    fun `status that is not a map is malformed`() {
        val mso = Map().apply { put(UnicodeString("status"), UnicodeString("nope")) }

        val result = validator.validate(mso) as MsoStatusListValidationResult.Malformed
        assertEquals(STATUS_REFERENCE_MALFORMED, result.errorCode)
    }

    @Test
    fun `status_list that is not a map is malformed`() {
        val mso = Map().apply {
            put(UnicodeString("status"), Map().apply {
                put(UnicodeString("status_list"), UnicodeString("nope"))
            })
        }

        val result = validator.validate(mso) as MsoStatusListValidationResult.Malformed
        assertEquals(STATUS_REFERENCE_MALFORMED, result.errorCode)
    }

    @Test
    fun `missing uri is malformed`() {
        val statusList = Map().apply { put(UnicodeString("idx"), UnsignedInteger(0)) }
        val mso = Map().apply {
            put(UnicodeString("status"), Map().apply { put(UnicodeString("status_list"), statusList) })
        }

        val result = validator.validate(mso) as MsoStatusListValidationResult.Malformed
        assertEquals(STATUS_REFERENCE_MALFORMED, result.errorCode)
    }

    @Test
    fun `missing idx is malformed`() {
        val statusList = Map().apply {
            put(UnicodeString("uri"), UnicodeString("https://example.com/statuslists/1"))
        }
        val mso = Map().apply {
            put(UnicodeString("status"), Map().apply { put(UnicodeString("status_list"), statusList) })
        }

        val result = validator.validate(mso) as MsoStatusListValidationResult.Malformed
        assertEquals(STATUS_REFERENCE_MALFORMED, result.errorCode)
    }

    @Test
    fun `idx that is not an unsigned int is malformed`() {
        val result = validator.validate(
            msoWith(
                uri = UnicodeString("https://example.com/statuslists/1"),
                idx = NegativeInteger(-1)
            )
        ) as MsoStatusListValidationResult.Malformed

        assertEquals(STATUS_REFERENCE_MALFORMED, result.errorCode)
    }

    @Test
    fun `uri that is not text is malformed`() {
        val result = validator.validate(
            msoWith(uri = UnsignedInteger(1), idx = UnsignedInteger(0))
        ) as MsoStatusListValidationResult.Malformed

        assertEquals(STATUS_REFERENCE_MALFORMED, result.errorCode)
    }

    private fun msoWithStatusList(uri: String, idx: Long): Map =
        msoWith(UnicodeString(uri), UnsignedInteger(idx))

    private fun msoWith(uri: co.nstant.`in`.cbor.model.DataItem, idx: co.nstant.`in`.cbor.model.DataItem): Map {
        val statusList = Map().apply {
            put(UnicodeString("uri"), uri)
            put(UnicodeString("idx"), idx)
        }
        return Map().apply {
            put(UnicodeString("status"), Map().apply { put(UnicodeString("status_list"), statusList) })
        }
    }
}
