package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_EXPIRED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_INVALID_SIGNATURE
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_MALFORMED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_UNTRUSTED_ISSUER
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_URI_MISMATCH
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.testHelpers.MdocStatusListFixtures
import io.mosip.vercred.vcverifier.testHelpers.MdocStatusListFixtures.STATUS_URI
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.security.cert.X509Certificate

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
    fun `issuer certificate is the unprotected header even when the protected header differs`() {
        val attacker = MdocStatusListFixtures.generateKeyMaterial().certificate
        val issuerAuth = issuerAuth(
            protectedCertificate = attacker,
            unprotectedCertificate = issuerCertificate
        )

        val selected = validator.issuerCertificateFrom(issuerAuth)

        assertTrue(selected!!.encoded.contentEquals(issuerCertificate.encoded))
    }

    @Test
    fun `certificate present only in the protected header is not the issuer certificate`() {
        val attacker = MdocStatusListFixtures.generateKeyMaterial().certificate
        val issuerAuth = issuerAuth(protectedCertificate = attacker, unprotectedCertificate = null)

        assertNull(validator.issuerCertificateFrom(issuerAuth))
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

    private fun issuerAuth(
        protectedCertificate: X509Certificate?,
        unprotectedCertificate: X509Certificate?
    ): Array {
        return Array().apply {
            add(ByteString(encode(headerMap(protectedCertificate))))
            add(headerMap(unprotectedCertificate))
            add(ByteString(byteArrayOf()))
            add(ByteString(byteArrayOf(0)))
        }
    }

    private fun headerMap(certificate: X509Certificate?): Map {
        return Map().apply {
            if (certificate != null) {
                put(UnsignedInteger(33), ByteString(certificate.encoded))
            }
        }
    }

    private fun encode(dataItem: DataItem): ByteArray =
        ByteArrayOutputStream().also { CborEncoder(it).encode(dataItem) }.toByteArray()
}
