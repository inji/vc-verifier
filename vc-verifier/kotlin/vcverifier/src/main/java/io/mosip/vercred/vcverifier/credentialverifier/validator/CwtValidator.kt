package io.mosip.vercred.vcverifier.credentialverifier.validator

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_PROCESSING_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_GENERIC
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_PROCESSING_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_FIELD
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_EMPTY_VC_CWT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXCEPTION_DURING_VALIDATION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_HEX_VC_CWT
import io.mosip.vercred.vcverifier.data.ValidationStatus

import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.Util.hexToBytes
import io.mosip.vercred.vcverifier.utils.Util.validateNumericDate

class CwtValidator {

    fun validate(credential: String): ValidationStatus {
        try {
            if (credential.isEmpty()) {
                throw ValidationException(
                    ERROR_MESSAGE_EMPTY_VC_CWT,
                    ERROR_CODE_INVALID + "EMPTY"
                )
            }

            if (!isValidHex(credential)) {
                throw ValidationException(
                    ERROR_MESSAGE_INVALID_HEX_VC_CWT,
                    ERROR_CODE_INVALID + "HEX"
                )
            }

            val coseObj = decodeCose(credential)

            validateCoseStructure(coseObj)

            val protectedHeader = decodeProtectedHeader(coseObj)
            validateProtectedHeader(protectedHeader)

            val claims = decodeCwtClaims(coseObj)
            validateCwtStructure(claims)
            validateNumericDates(claims)
            return ValidationStatus("", "")
        } catch (e: ValidationException) {
            return ValidationStatus(e.errorMessage, e.errorCode)
        } catch (e: Exception) {
            return ValidationStatus(
                "${EXCEPTION_DURING_VALIDATION}${e.message}",
                ERROR_CODE_GENERIC
            )
        }
    }


    private fun validateCoseStructure(coseObj: CBORObject) {

        if (coseObj.type != CBORType.Array) {
            throw ValidationException(
                ERROR_INVALID_FIELD + "COSE_Sign1 must be a CBOR array",
                ERROR_CODE_INVALID + "COSE_STRUCTURE"
            )
        }

        if (coseObj.size() != 4) {
            throw ValidationException(
                ERROR_INVALID_FIELD + "COSE_Sign1 must have exactly 4 elements",
                ERROR_CODE_INVALID + "COSE_STRUCTURE"
            )
        }

        // Index 0: Protected header
        if (coseObj[0].type != CBORType.ByteString) {
            throw ValidationException(
                ERROR_INVALID_FIELD + "Protected header must be a CBOR byte string (bstr)",
                ERROR_CODE_INVALID + "PROTECTED_HEADER"
            )
        }

        // Index 1: Unprotected header
        if (coseObj[1].type != CBORType.Map) {
            throw ValidationException(
                ERROR_INVALID_FIELD + "Unprotected header must be a CBOR map",
                ERROR_CODE_INVALID + "UNPROTECTED_HEADER"
            )
        }

        // Index 2: Payload (The CWT Claims)
        if (coseObj[2].type != CBORType.ByteString) {
            throw ValidationException(
                ERROR_INVALID_FIELD + "Payload must be a CBOR byte string (bstr)",
                ERROR_CODE_INVALID + "PAYLOAD"
            )
        }

        // Index 3: Signature
        if (coseObj[3].type != CBORType.ByteString) {
            throw ValidationException(
                ERROR_INVALID_FIELD + "Signature must be a CBOR byte string (bstr)",
                ERROR_CODE_INVALID + "SIGNATURE"
            )
        }
    }


    private fun validateProtectedHeader(protectedHeader: CBORObject) {

        if (protectedHeader.type != CBORType.Map) {
            throw ValidationException(
                ERROR_INVALID_FIELD + "Protected header must decode to a CBOR map",
                ERROR_CODE_INVALID + "PROTECTED_HEADER"
            )
        }

        val ALG = CBORObject.FromObject(1)

        if (!protectedHeader.ContainsKey(ALG)) {
            throw ValidationException(
                ERROR_INVALID_FIELD + "Missing alg in protected header",
                ERROR_CODE_MISSING + "ALG"
            )
        }

        if (!protectedHeader[ALG].isNumber) {
            throw ValidationException(
                ERROR_INVALID_FIELD + "alg must be an integer",
                ERROR_CODE_INVALID + "ALG"
            )
        }
    }


    private fun validateCwtStructure(claims: CBORObject) {

        if (claims.type != CBORType.Map) {
            throw ValidationException(
                ERROR_INVALID_FIELD + "CWT payload must be a CBOR map",
                ERROR_CODE_INVALID + "CWT_STRUCTURE"
            )
        }
    }


    private fun validateNumericDates(claims: CBORObject) {

        val EXP = CBORObject.FromObject(4)
        val NBF = CBORObject.FromObject(5)
        val IAT = CBORObject.FromObject(6)

        val now = System.currentTimeMillis() / 1000

        val exp = validateNumericDate(claims, EXP, "exp")
        val nbf = validateNumericDate(claims, NBF, "nbf")
        val iat = validateNumericDate(claims, IAT, "iat")

        // Expired Check
        if (exp != null && exp <= now) {
            throw ValidationException(
                ERROR_MESSAGE_VC_EXPIRED + " (exp=$exp, now=$now)",
                ERROR_CODE_VC_EXPIRED
            )
        }

        // Not Before Check
        if (nbf != null && nbf > now) {
            throw ValidationException(
                ERROR_CURRENT_DATE_BEFORE_PROCESSING_DATE + " (nbf=$nbf, now=$now)",
                ERROR_CODE_CURRENT_DATE_BEFORE_PROCESSING_DATE
            )
        }

        // Issued At Check
        if (iat != null && iat > now) {
            throw ValidationException(
                ERROR_INVALID_FIELD + "CWT issued in the future (iat=$iat, now=$now)",
                ERROR_CODE_INVALID + "IAT"
            )
        }
    }



    private fun decodeCose(credential: String): CBORObject {
        val bytes = hexToBytes(credential)
        return CBORObject.DecodeFromBytes(bytes)
    }

    private fun decodeProtectedHeader(coseObj: CBORObject): CBORObject {
        val bytes = coseObj[0].GetByteString()
        return CBORObject.DecodeFromBytes(bytes)
    }

    private fun decodeCwtClaims(coseObj: CBORObject): CBORObject {
        val payloadBytes = coseObj[2].GetByteString()
        return CBORObject.DecodeFromBytes(payloadBytes)
    }

    private fun isValidHex(credential: String): Boolean {
        val hexRegex = "^[0-9a-fA-F]+$".toRegex()
        return credential.matches(hexRegex)
    }

}