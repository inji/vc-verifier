package io.mosip.vercred.vcverifier.utils

import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ALGORITHMS_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.DESCRIPTION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_ALGORITHM_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CREDENTIAL_SUBJECT_NON_NULL_OBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_DESCRIPTION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_FIELD
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MISSING_REQUIRED_FIELDS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_NAME
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_PROOF_TYPE_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_TYPE_VERIFIABLE_CREDENTIAL
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUER
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.JWS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.LANGUAGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.NAME
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF_TYPES_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TYPE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VERIFIABLE_CREDENTIAL
import io.mosip.vercred.vcverifier.exception.ValidationException
import org.json.JSONArray
import org.json.JSONObject

class ValidationHelper {


    fun checkMandatoryFields(vcJsonObject: JSONObject, fields: List<String>) {

        for (field in fields) {
            val keys = field.split(".")
            var currentJson: JSONObject? = vcJsonObject

            for (key in keys) {
                if (currentJson != null && currentJson.has(key)) {
                    if (currentJson[key] is JSONObject) {
                        currentJson = currentJson.getJSONObject(key)
                    } else {
                        break
                    }
                } else {
                    val specificErrorCode = "$ERROR_CODE_MISSING${field.replace(".", "_").uppercase()}"
                    throw ValidationException( "$ERROR_MISSING_REQUIRED_FIELDS$field", specificErrorCode)
                }
            }
        }
    }

    fun validateProof(vcJsonString: String) {
        val vcJsonObject = JSONObject(vcJsonString)

        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(vcJsonString)
        val ldProof : LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)

        if(vcJsonObject.getJSONObject(PROOF).has(JWS)){
            val jwsToken: String = ldProof.jws
            val algorithmName: String = JWSObject.parse(jwsToken).header.algorithm.name
            if(jwsToken.isEmpty() || !ALGORITHMS_SUPPORTED.contains(algorithmName)){
                throw ValidationException( ERROR_MESSAGE_ALGORITHM_NOT_SUPPORTED , "${ERROR_CODE_INVALID}${ALGORITHM.uppercase()}")
            }
        }

        val ldProofType: String = ldProof.type
        if (!PROOF_TYPES_SUPPORTED.contains(ldProofType)) {
            throw ValidationException( ERROR_MESSAGE_PROOF_TYPE_NOT_SUPPORTED, "${ERROR_CODE_INVALID}${PROOF.uppercase()}_${TYPE.uppercase()}")
        }
        if (ldProofType == "DataIntegrityProof") {
            val cryptosuite = vcJsonObject.getJSONObject(PROOF).optString("cryptosuite")
            if (cryptosuite !in setOf("eddsa-rdfc-2022", "ecdsa-rdfc-2019")) {
                throw ValidationException(
                    ERROR_MESSAGE_PROOF_TYPE_NOT_SUPPORTED,
                    "${ERROR_CODE_INVALID}${PROOF.uppercase()}_CRYPTOSUITE"
                )
            }
        }
    }

    fun validateId(vcJsonObject: JSONObject){
        if(vcJsonObject.has(ID) && !Util.isValidUri(vcJsonObject.getString(ID))) {
            throw ValidationException("$ERROR_INVALID_URI$ID", "${ERROR_CODE_INVALID}${ID}")
        }
    }

    fun validateType(vcJsonObject: JSONObject){

        if(vcJsonObject.has(TYPE)){
            vcJsonObject.optJSONArray(TYPE)?.let { types ->
                if (!Util.jsonArrayToList(types).contains(VERIFIABLE_CREDENTIAL)) {
                    throw ValidationException(ERROR_MESSAGE_TYPE_VERIFIABLE_CREDENTIAL, "${ERROR_CODE_INVALID}${TYPE.uppercase()}")
                }
            }
        }

    }

    fun validateIssuer(vcJsonObject: JSONObject){
        if(vcJsonObject.has(ISSUER)){
            val issuerId = Util.getId(vcJsonObject[ISSUER])
            if(issuerId == null || !Util.isValidUri(issuerId)) {
                throw ValidationException( "$ERROR_INVALID_URI${ISSUER}", "${ERROR_CODE_INVALID}${ISSUER.uppercase()}")
            }
        }
    }

    fun validateNameAndDescription(vcJsonObject: JSONObject) {

        val nameDescriptionList: List<Pair<String, String>> = listOf(
            NAME to ERROR_MESSAGE_NAME,
            DESCRIPTION to ERROR_MESSAGE_DESCRIPTION
        )

        nameDescriptionList.forEach { fieldPair ->
            if(vcJsonObject.has(fieldPair.first)){
                when (val fieldValue = vcJsonObject[fieldPair.first]) {
                    is String -> return
                    is JSONArray -> checkForLanguageObject(fieldValue, fieldPair)
                    else -> {
                        throw ValidationException(fieldPair.second, "${ERROR_CODE_INVALID}${fieldPair.first.uppercase()}")
                    }
                }
            }

        }

    }

    private fun checkForLanguageObject(
        nameOrDescriptionArray: JSONArray,
        fieldPair: Pair<String, String>
    ) {
        for (i in 0 until nameOrDescriptionArray.length()) {
            val nameObject = nameOrDescriptionArray.getJSONObject(i)
            if (!nameObject.has(LANGUAGE)) {
                throw ValidationException(fieldPair.second, "${ERROR_CODE_INVALID}${fieldPair.first.uppercase()}")
            }
        }
    }

    fun validateCredentialSubject(vcJsonObject: JSONObject) {
        val credentialSubject = vcJsonObject[CREDENTIAL_SUBJECT]
        validateJsonObjectOrArray(CREDENTIAL_SUBJECT, credentialSubject, ::validateSingleCredentialObject,
            ERROR_CREDENTIAL_SUBJECT_NON_NULL_OBJECT
        )
    }

    fun validateFieldsByIdAndType(vcJsonObject: JSONObject, fieldName: String, idMandatoryFields: List<String>) {
        val fieldValue = vcJsonObject[fieldName]
        validateJsonObjectOrArray(fieldName, fieldValue, { obj -> validateSingleObject(fieldName, obj, idMandatoryFields) }, "$ERROR_INVALID_FIELD$fieldName")
    }

    private fun validateJsonObjectOrArray(
        fieldName: String,
        value: Any,
        validator: (JSONObject) -> String,
        errorMessage: String
    ) {
        when (value) {
            is JSONArray -> {
                for (i in 0 until value.length()) {
                    val jsonObject = value.getJSONObject(i)
                    val result = validator(jsonObject)
                    if (result.isNotEmpty()) throw ValidationException(errorMessage, "${ERROR_CODE_INVALID}${fieldName.uppercase()}")
                }
            }
            is JSONObject -> validator(value)
            else -> throw ValidationException(errorMessage, "${ERROR_CODE_INVALID}${fieldName.uppercase()}")
        }
    }

    private fun validateSingleCredentialObject(credentialSubjectObject: JSONObject): String {
        if (credentialSubjectObject.has(ID) && !Util.isValidUri(credentialSubjectObject.optString(ID))) {
            throw ValidationException("$ERROR_INVALID_URI$CREDENTIAL_SUBJECT.$ID", "$ERROR_CODE_INVALID${CREDENTIAL_SUBJECT}${ID.uppercase()}")
        }
        return ""
    }

    private fun validateSingleObject(fieldName: String, fieldValueObject: JSONObject, idMandatoryFields: List<String>): String {
        if (!fieldValueObject.has(TYPE)) {
            throw ValidationException( "$ERROR_MISSING_REQUIRED_FIELDS$fieldName.$TYPE", "$ERROR_CODE_MISSING${fieldName.uppercase()}_${TYPE.uppercase()}")
        } else if (fieldValueObject.optString(TYPE).isNullOrBlank()) {
            throw ValidationException("$fieldName.$TYPE cannot be null or empty.", "$ERROR_CODE_INVALID${fieldName.uppercase()}_${TYPE.uppercase()}")
        }

        val isIDMandatoryField = idMandatoryFields.contains(fieldName)
        if (isIDMandatoryField) {
            if (!fieldValueObject.has(ID)) {
                throw ValidationException("$ERROR_MISSING_REQUIRED_FIELDS$fieldName.$ID", "$ERROR_CODE_MISSING${fieldName.uppercase()}_${ID.uppercase()}")
            } else if (fieldValueObject.optString(ID).isNullOrBlank()) {
                throw ValidationException("$fieldName.$ID cannot be null or empty.", "$ERROR_CODE_INVALID${fieldName.uppercase()}_${ID.uppercase()}")
            }
        }
        fieldValueObject.optString(ID).takeIf { it.isNotEmpty() }?.let { id ->
            if (!Util.isValidUri(id)) {
                throw ValidationException( "$ERROR_INVALID_URI$fieldName.$ID", "$ERROR_CODE_INVALID${fieldName.uppercase()}_${ID.uppercase()}")
            }
        }

        return ""
    }


}
