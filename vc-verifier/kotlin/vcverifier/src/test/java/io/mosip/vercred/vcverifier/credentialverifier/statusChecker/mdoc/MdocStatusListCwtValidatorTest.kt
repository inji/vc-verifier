package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_EXPIRED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_INVALID_SIGNATURE
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_MALFORMED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_UNTRUSTED_ISSUER
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_URI_MISMATCH
import io.mosip.vercred.vcverifier.testHelpers.MdocStatusListFixtures
import io.mosip.vercred.vcverifier.testHelpers.MdocStatusListFixtures.STATUS_URI
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MdocStatusListCwtValidatorTest {

    private val validator = MdocStatusListCwtValidator()

    @Test
    fun `valid CWT returns bits lst and ttl`() {
        val cwt = MdocStatusListFixtures.statusListCwt(bits = 1, valuesAtIndex = intArrayOf(0))

        val validated = validator.validate(cwt, STATUS_URI)

        assertEquals(1, validated.bits)
        assertTrue(validated.compressedLst.isNotEmpty())
        assertEquals(MdocStatusListFixtures.TTL_SECONDS, validated.ttlSeconds)
    }

    @Test
    fun `ttl is not treated as expiry`() {
        val cwt = MdocStatusListFixtures.statusListCwt(
            bits = 1,
            valuesAtIndex = intArrayOf(0),
            ttlSeconds = 1
        )

        val validated = validator.validate(cwt, STATUS_URI)

        assertEquals(1L, validated.ttlSeconds)
    }

    @Test
    fun `missing ttl is allowed`() {
        val cwt = MdocStatusListFixtures.statusListCwt(
            bits = 1,
            valuesAtIndex = intArrayOf(0),
            ttlSeconds = null
        )

        val validated = validator.validate(cwt, STATUS_URI)

        assertNull(validated.ttlSeconds)
    }

    @Test
    fun `wrong typ is malformed`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validator.validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    typ = "application/cwt"
                ),
                STATUS_URI
            )
        }
        assertEquals(STATUS_LIST_MALFORMED, exception.errorCode)
    }

    @Test
    fun `untagged CWT is malformed`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validator.validate(
                MdocStatusListFixtures.signCwt(
                    claims = co.nstant.`in`.cbor.model.Map(),
                    tag = 0
                ),
                STATUS_URI
            )
        }
        assertEquals(STATUS_LIST_MALFORMED, exception.errorCode)
    }

    @Test
    fun `bad signature fails`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validator.validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    corruptSignature = true
                ),
                STATUS_URI
            )
        }
        assertEquals(STATUS_LIST_INVALID_SIGNATURE, exception.errorCode)
    }

    @Test
    fun `wrong sub fails`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validator.validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    uri = MdocStatusListFixtures.WRONG_STATUS_URI
                ),
                STATUS_URI
            )
        }
        assertEquals(STATUS_LIST_URI_MISMATCH, exception.errorCode)
    }

    @Test
    fun `expired CWT fails`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validator.validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    exp = MdocStatusListFixtures.EXPIRED_EXP
                ),
                STATUS_URI
            )
        }
        assertEquals(STATUS_LIST_EXPIRED, exception.errorCode)
    }

    @Test
    fun `missing x5chain is untrusted`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validator.validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    includeX5chain = false
                ),
                STATUS_URI
            )
        }
        assertEquals(STATUS_LIST_UNTRUSTED_ISSUER, exception.errorCode)
    }
}
