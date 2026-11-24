package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_EXPIRED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_NOT_ACTIVE
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_INVALID_SIGNATURE
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_MALFORMED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_UNTRUSTED_ISSUER
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_URI_MISMATCH
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PROFILE_UNSUPPORTED
import io.mosip.vercred.vcverifier.testHelpers.MdocStatusListFixtures
import io.mosip.vercred.vcverifier.testHelpers.MdocStatusListFixtures.STATUS_URI
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MdocStatusListCwtValidatorTest {

    private val validator = MdocStatusListCwtValidator()
    private val issuerCertificate = MdocStatusListFixtures.keyMaterial.certificate

    @Test
    fun `valid CWT returns bits lst and ttl`() {
        val cwt = MdocStatusListFixtures.statusListCwt(bits = 1, valuesAtIndex = intArrayOf(0))

        val validated = validate(cwt)

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

        val validated = validate(cwt)

        assertEquals(1L, validated.ttlSeconds)
    }

    @Test
    fun `zero ttl is malformed`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    ttlSeconds = 0
                )
            )
        }
        assertEquals(STATUS_LIST_MALFORMED, exception.errorCode)
    }

    @Test
    fun `missing ttl is allowed`() {
        val cwt = MdocStatusListFixtures.statusListCwt(
            bits = 1,
            valuesAtIndex = intArrayOf(0),
            ttlSeconds = null
        )

        val validated = validate(cwt)

        assertNull(validated.ttlSeconds)
    }

    @Test
    fun `wrong typ is malformed`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    typ = "application/cwt"
                )
            )
        }
        assertEquals(STATUS_LIST_MALFORMED, exception.errorCode)
    }

    @Test
    fun `deeply nested CBOR is malformed`() {
        val nested = ByteArray(50_000) { 0x81.toByte() } + byteArrayOf(0x00)
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validate(nested)
        }
        assertEquals(STATUS_LIST_MALFORMED, exception.errorCode)
    }

    @Test
    fun `untagged CWT is malformed`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validate(
                MdocStatusListFixtures.signCwt(
                    claims = co.nstant.`in`.cbor.model.Map(),
                    tag = 0
                )
            )
        }
        assertEquals(STATUS_LIST_MALFORMED, exception.errorCode)
    }

    @Test
    fun `bad signature fails`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    corruptSignature = true
                )
            )
        }
        assertEquals(STATUS_LIST_INVALID_SIGNATURE, exception.errorCode)
    }

    @Test
    fun `wrong sub fails`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    uri = MdocStatusListFixtures.WRONG_STATUS_URI
                )
            )
        }
        assertEquals(STATUS_LIST_URI_MISMATCH, exception.errorCode)
    }

    @Test
    fun `missing exp is allowed`() {
        val validated = validate(
            MdocStatusListFixtures.statusListCwt(
                bits = 1,
                valuesAtIndex = intArrayOf(0),
                exp = null
            )
        )

        assertEquals(1, validated.bits)
    }

    @Test
    fun `nbf in the future is not active`() {
        val now = 1_000L
        val validatorAtNow = MdocStatusListCwtValidator(nowSeconds = { now })

        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validatorAtNow.validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    nbf = 2_000L,
                    exp = 3_000L
                ),
                STATUS_URI,
                issuerCertificate
            )
        }
        assertEquals(STATUS_LIST_NOT_ACTIVE, exception.errorCode)
    }

    @Test
    fun `nbf equal to now is valid`() {
        val now = 2_000L
        val validatorAtNow = MdocStatusListCwtValidator(nowSeconds = { now })

        val validated = validatorAtNow.validate(
            MdocStatusListFixtures.statusListCwt(
                bits = 1,
                valuesAtIndex = intArrayOf(0),
                nbf = now,
                exp = 3_000L
            ),
            STATUS_URI,
            issuerCertificate
        )

        assertEquals(1, validated.bits)
    }

    @Test
    fun `missing nbf is allowed`() {
        val validated = validate(
            MdocStatusListFixtures.statusListCwt(
                bits = 1,
                valuesAtIndex = intArrayOf(0),
                nbf = null
            )
        )

        assertEquals(1, validated.bits)
    }

    @Test
    fun `exp equal to now is expired`() {
        val now = 1_700_000_100L
        val validatorAtNow = MdocStatusListCwtValidator(nowSeconds = { now })

        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validatorAtNow.validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    exp = now
                ),
                STATUS_URI,
                issuerCertificate
            )
        }
        assertEquals(STATUS_LIST_EXPIRED, exception.errorCode)
    }

    @Test
    fun `expired CWT fails`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    exp = MdocStatusListFixtures.EXPIRED_EXP
                )
            )
        }
        assertEquals(STATUS_LIST_EXPIRED, exception.errorCode)
    }

    @Test
    fun `x5chain in the protected header is accepted`() {
        val validated = validate(
            MdocStatusListFixtures.statusListCwt(
                bits = 1,
                valuesAtIndex = intArrayOf(0),
                x5chainInProtectedHeader = true
            )
        )
        assertEquals(1, validated.bits)
    }

    @Test
    fun `missing x5chain is untrusted`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    includeX5chain = false
                )
            )
        }
        assertEquals(STATUS_LIST_UNTRUSTED_ISSUER, exception.errorCode)
    }

    @Test
    fun `CWT signed by a different key is untrusted even when the signature verifies`() {
        val attacker = MdocStatusListFixtures.generateKeyMaterial()
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    keyMaterial = attacker
                )
            )
        }
        assertEquals(STATUS_LIST_UNTRUSTED_ISSUER, exception.errorCode)
    }

    @Test
    fun `bits that wrap to a supported Int are unsupported`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 1,
                    valuesAtIndex = intArrayOf(0),
                    bitsClaim = (1L shl 32) + 1L
                )
            )
        }
        assertEquals(STATUS_PROFILE_UNSUPPORTED, exception.errorCode)
    }

    @Test
    fun `bits 4 is unsupported`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            validate(
                MdocStatusListFixtures.statusListCwt(
                    bits = 4,
                    valuesAtIndex = intArrayOf(0)
                )
            )
        }
        assertEquals(STATUS_PROFILE_UNSUPPORTED, exception.errorCode)
    }

    @Test
    fun `CWT signer certificate issued by the mDoc issuer is authorized`() {
        val statusSigner = MdocStatusListFixtures.keyMaterialIssuedBy()
        val validated = validate(
            MdocStatusListFixtures.statusListCwt(
                bits = 1,
                valuesAtIndex = intArrayOf(0),
                keyMaterial = statusSigner
            )
        )
        assertEquals(1, validated.bits)
    }

    private fun validate(cwt: ByteArray) =
        validator.validate(cwt, STATUS_URI, issuerCertificate)
}
