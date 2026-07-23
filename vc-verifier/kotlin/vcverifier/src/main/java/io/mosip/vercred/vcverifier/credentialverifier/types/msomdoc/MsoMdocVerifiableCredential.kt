package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_GENERIC
import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.validator.MsoMdocValidator
import io.mosip.vercred.vcverifier.credentialverifier.verifier.MsoMdocVerifier
import io.mosip.vercred.vcverifier.data.ValidationStatus
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import java.io.ByteArrayInputStream
import java.util.logging.Logger

class MsoMdocVerifiableCredential : VerifiableCredential {

    private val logger = Logger.getLogger(MsoMdocVerifiableCredential::class.java.name)


    override fun validate(credential: String): ValidationStatus {
        try {
            MsoMdocValidator().validate(credential)
            return ValidationStatus("", "")
        } catch (exception: Exception) {
            return when(exception){
                is ValidationException -> {
                    ValidationStatus(exception.errorMessage, exception.errorCode)
                }
                else -> {
                    ValidationStatus("${CredentialValidatorConstants.EXCEPTION_DURING_VALIDATION}${exception.message}", ERROR_CODE_GENERIC)
                }
            }

        }
    }

    override fun verify(credential: String): Boolean {
        return MsoMdocVerifier().verify(credential)
    }

    fun parse(credential: String): MsoMdocCredentialData {
        val decodedData: ByteArray = try {
            Base64Decoder().decodeFromBase64Url(credential)
        } catch (exception: Exception) {
            logger.severe("Error occurred while base64Url decoding the credential " + exception.message)
            throw RuntimeException("Error on decoding base64Url encoded data " + exception.message)
        }

        val cbors: List<DataItem>
        try {
            cbors = CborDecoder(ByteArrayInputStream(decodedData)).decode()
        } catch (exception: Exception) {
            logger.severe("Error occurred while CBOR decoding the credential " + exception.message)
            throw RuntimeException("Error on decoding CBOR encoded data " + exception.message)

        }
        val decodedCredential = cbors[0] as Map
        val issuerSigned: DataItem = getIssuerSigned(decodedCredential)

        val issuerAuth: Array = getIssuerAuth(issuerSigned)
        val issuerSignedNamespaces: Map = (issuerSigned["nameSpaces"]) as Map
        val mso = issuerAuth.extractMso()
        val docType = mso["docType"]


        return MsoMdocCredentialData(
            docType,
            issuerSigned = MsoMdocCredentialData.IssuerSigned(issuerAuth, issuerSignedNamespaces),
            mso
        )
    }

    private fun getIssuerAuth(issuerSigned: DataItem): Array {
        val issuerAuth: DataItem = (issuerSigned["issuerAuth"])
        if(issuerAuth.majorType == MajorType.ARRAY) {
            return issuerAuth as Array
        }


        throw RuntimeException("Invalid IssuerAuth structure in mDoc")
    }

    private fun getIssuerSigned(
        decodedCredential: Map
    ): DataItem {
        val issuerSigned: DataItem =
            (if ((decodedCredential).keys.toString().contains("documents")) {
                (decodedCredential["documents"][0] as Map)["issuerSigned"]
            } else if (decodedCredential.keys.toString().contains("issuerSigned")) {
                (decodedCredential)["issuerSigned"]
            } else {
                decodedCredential
            })
        return issuerSigned
    }
}

operator fun DataItem.get(name: String): DataItem {
    check(this.majorType == MajorType.MAP)
    this as Map
    return this.get(UnicodeString(name))
}

operator fun DataItem.get(index: Int): DataItem {
    check(this.majorType == MajorType.ARRAY)
    this as Array
    return this.dataItems[index]
}
