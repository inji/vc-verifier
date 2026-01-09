package io.mosip.vercred.vcverifier.credentialverifier.validator

import com.upokecenter.cbor.CBORObject
import io.ipfs.multibase.Base16.bytesToHex
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*


class CwtValidatorTest {

    @BeforeEach
    fun setup() {
    }

    private val validator = CwtValidator()

    private fun createCoseHex(
        protected: CBORObject = CBORObject.NewMap().apply { Add(1, -7) },
        unprotected: CBORObject = CBORObject.NewMap(),
        payload: CBORObject = CBORObject.NewMap(),
        signature: ByteArray = ByteArray(32)
    ): String {
        val coseArray = CBORObject.NewArray().apply {
            Add(protected.EncodeToBytes())
            Add(unprotected)
            Add(payload.EncodeToBytes())
            Add(signature)
        }
        return bytesToHex(coseArray.EncodeToBytes())
    }

    private fun cborMapWithDuplicateKey(
        key: Int,
        firstValue: CBORObject,
        secondValue: CBORObject
    ): ByteArray {
        // CBOR map with 2 pairs, same key repeated
        val map = CBORObject.NewArray().apply {
            Add(key)
            Add(firstValue)
            Add(key)
            Add(secondValue)
        }

        // Encode as a CBOR map manually
        return CBORObject.NewMap().apply {
            // placeholder, replaced below
        }.let {
            // Major type 5 (map), length 2
            byteArrayOf(0xA2.toByte()) +
                    map[0].EncodeToBytes() +
                    map[1].EncodeToBytes() +
                    map[2].EncodeToBytes() +
                    map[3].EncodeToBytes()
        }
    }


    @Test
    fun `test - duplicate CWT claim keys should fail`() {

        val duplicateClaimsBytes = cborMapWithDuplicateKey(
            key = 4, // exp
            firstValue = CBORObject.FromObject(9999999999L),
            secondValue = CBORObject.FromObject(8888888888L)
        )

        val coseArray = CBORObject.NewArray().apply {
            Add(CBORObject.NewMap().apply { Add(1, -7) }.EncodeToBytes())
            Add(CBORObject.NewMap())
            Add(duplicateClaimsBytes)
            Add(ByteArray(32))
        }

        val hex = coseArray.EncodeToBytes().joinToString("") { "%02x".format(it) }

        val result = validator.validate(hex)

        assertEquals(
            CredentialValidatorConstants.ERROR_CODE_GENERIC,
            result.validationErrorCode
        )
        assertTrue(
            result.validationMessage.contains("Duplicate"),
            "Expected duplicate key decoding failure"
        )
    }


    @Test
    fun `validate - empty string should fail`() {
        val result = validator.validate("")
        assertEquals(CredentialValidatorConstants.ERROR_CODE_INVALID + "EMPTY", result.validationErrorCode)
        assertEquals(CredentialValidatorConstants.ERROR_MESSAGE_EMPTY_VC_CWT, result.validationMessage)
    }

    @Test
    fun `test - invalid hex string characters`() {
        val result = validator.validate("NOT_HEX_123")
        assertEquals(CredentialValidatorConstants.ERROR_CODE_INVALID + "HEX", result.validationErrorCode)
        assertEquals(CredentialValidatorConstants.ERROR_MESSAGE_INVALID_HEX_VC_CWT, result.validationMessage)
    }

    @Test
    fun `test - COSE not an array`() {
        val invalidCose = CBORObject.FromObject("This is just a string").EncodeToBytes()
        val result = validator.validate(invalidCose.joinToString("") { "%02x".format(it) })
        assertTrue(result.validationErrorCode.contains("COSE_STRUCTURE"))
    }

    @Test
    fun `test - alg is not an integer`() {
        val badHeader = CBORObject.NewMap().apply { Add(1, "ES256") }
        val hex = createCoseHex(protected = badHeader)
        val result = validator.validate(hex)
        assertEquals(CredentialValidatorConstants.ERROR_CODE_INVALID + "ALG", result.validationErrorCode)
    }

    @Test
    fun `test - payload index is not a byte string`() {
        val coseArray = CBORObject.NewArray().apply {
            Add(CBORObject.NewMap().EncodeToBytes())
            Add(CBORObject.NewMap())
            Add(CBORObject.NewMap())
            Add(ByteArray(32))
        }
        val hex = coseArray.EncodeToBytes().joinToString("") { "%02x".format(it) }
        val result = validator.validate(hex)
        assertEquals(CredentialValidatorConstants.ERROR_CODE_INVALID + "PAYLOAD", result.validationErrorCode)
    }

    @Test
    fun `test - protected header missing alg`() {
        val hex = createCoseHex(protected = CBORObject.NewMap())
        val result = validator.validate(hex)
        assertEquals(CredentialValidatorConstants.ERROR_CODE_MISSING + "ALG", result.validationErrorCode)
        assertTrue(result.validationMessage.contains("Missing alg"))
    }

    @Test
    fun `test - COSE array size is not 4`() {
        val badArray = CBORObject.NewArray().apply { Add(1); Add(2); Add(3) }
        val hex = badArray.EncodeToBytes().joinToString("") { "%02x".format(it) }
        val result = validator.validate(hex)
        assertTrue(result.validationMessage.contains("exactly 4 elements"))
    }

    @Test
    fun `test - VC is expired`() {
        val past = (System.currentTimeMillis() / 1000) - 500
        val claims = CBORObject.NewMap().apply { Add(4, past) } // 4: exp
        val result = validator.validate(createCoseHex(payload = claims))
        assertEquals(CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED, result.validationErrorCode)
    }

    @Test
    fun `test - nbf is in future`() {
        val future = (System.currentTimeMillis() / 1000) + 1000
        val claims = CBORObject.NewMap().apply { Add(5, future) } // 5: nbf
        val result = validator.validate(createCoseHex(payload = claims))
        assertEquals(CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_PROCESSING_DATE, result.validationErrorCode)
    }

    @Test
    fun `test - iat is in future`() {
        val future = (System.currentTimeMillis() / 1000) + 1000
        val claims = CBORObject.NewMap().apply { Add(6, future) } // 6: iat
        val result = validator.validate(createCoseHex(payload = claims))
        assertEquals(CredentialValidatorConstants.ERROR_CODE_INVALID + "IAT", result.validationErrorCode)
    }

    @Test
    fun `validate - should return success when all structure headers and dates are valid`() {

        val now = System.currentTimeMillis() / 1000
        val expiration = now + 3600
        val notBefore = now - 60
        val issuedAt = now - 120


        val claimsMap = CBORObject.NewMap().apply {
            Add(4, expiration)
            Add(5, notBefore)
            Add(6, issuedAt)
            Add(1, "mosip-issuer")
        }


        val protectedHeaderMap = CBORObject.NewMap().apply {
            Add(1, -7)
        }


        val coseArray = CBORObject.NewArray().apply {
            Add(protectedHeaderMap.EncodeToBytes())
            Add(CBORObject.NewMap())
            Add(claimsMap.EncodeToBytes())
            Add(byteArrayOf(1, 2, 3, 4))
        }

        val validHex = coseArray.EncodeToBytes().joinToString("") { "%02x".format(it) }

        val result = validator.validate(validHex)

        assertEquals("", result.validationErrorCode, "Error code should be empty on success")
        assertEquals("", result.validationMessage, "Message should be empty on success")
    }
}
