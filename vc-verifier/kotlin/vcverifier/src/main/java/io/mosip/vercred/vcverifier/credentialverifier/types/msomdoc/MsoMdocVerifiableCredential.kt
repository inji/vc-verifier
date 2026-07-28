package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.Tag
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_GENERIC
import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.validator.MsoMdocValidator
import io.mosip.vercred.vcverifier.credentialverifier.verifier.MsoMdocVerifier
import io.mosip.vercred.vcverifier.data.ValidationStatus
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import java.io.ByteArrayInputStream
import java.util.logging.Logger

internal const val DOCUMENTS = "documents"
internal const val ISSUING_COUNTRY = "issuing_country"
internal const val X5C = 33L
internal const val DOC_TYPE = "docType"
internal const val DIGEST_ALGORITHM = "digestAlgorithm"
internal const val DIGEST_ID = "digestID"
internal const val VALUE_DIGESTS = "valueDigests"
internal const val NAME_SPACES = "nameSpaces"
private const val ISSUER_SIGNED = "issuerSigned"


private const val ISSUER_AUTH = "issuerAuth"

class MsoMdocVerifiableCredential : VerifiableCredential {

    private val logger = Logger.getLogger(MsoMdocVerifiableCredential::class.java.name)


    override fun validate(credential: String): ValidationStatus {
        try {
            MsoMdocValidator().validate(credential)
            return ValidationStatus("", "")
        } catch (exception: Exception) {
            return when (exception) {
                is ValidationException -> {
                    ValidationStatus(exception.errorMessage, exception.errorCode)
                }

                else -> {
                    ValidationStatus(
                        "${CredentialValidatorConstants.EXCEPTION_DURING_VALIDATION}${exception.message}",
                        ERROR_CODE_GENERIC
                    )
                }
            }

        }
    }

    override fun verify(credential: String): Boolean {
        return MsoMdocVerifier().verify(credential)
    }

    /**
     * returns MsoMdocCredentialData and a boolean flag indicating isLatest
     * isLatest flag indicates whether the VC is as per OpenID4VCI V1.0 spec or not
     * For backward compatibility purposes, the isLatest flag is used to validate against the OpenID4VCI 1.0 spec structure
     *
     * 1. Legacy
     *     - structure has the following
     *
     * ```json
     * {
     *   "docType": {...}
     *   "issuerSigned": {
     *     "issuerAuth": {..},
     *     "nameSpaces": {...}
     *   }
     * }
     * ```
     *
     * OR
     *
     * ```
     * {
     *      documents: [
     *        {
     *         "docType": {...}
     *         "issuerSigned": {
     *           "issuerAuth": {..},
     *           "nameSpaces": {...}
     *         }
     *       }
     *      ]
     * }
     * ```
     *
     * 2. Latest
     * - structure is as follows
     * ```json
     * {
     *     "issuerAuth": {..},
     *     "nameSpaces": {...}
     *   }
     * ```
     */
    fun parse(credential: String): Triple<Map, MsoMdocCredentialData, Boolean> {
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
        val (issuerAuth, issuerSignedNamespaces, isLatest) = getIssuerSignedData(decodedCredential)
        validateMsoPayload(issuerAuth, isLatest)
        val mso = issuerAuth.extractMso()
        val docType = mso.get(UnicodeString(DOC_TYPE))


        return Triple(
            decodedCredential,
            MsoMdocCredentialData(
                docType,
                issuerSigned = MsoMdocCredentialData.IssuerSigned(
                    issuerAuth,
                    issuerSignedNamespaces
                ),
                mso
            ),
            isLatest
        )
    }

    private fun getIssuerAuth(issuerSigned: DataItem): Array {
        val issuerAuth: DataItem = (issuerSigned[ISSUER_AUTH])
        if (issuerAuth.majorType == MajorType.ARRAY) {
            return issuerAuth as Array
        }


        throw RuntimeException("Invalid IssuerAuth structure in mDoc")
    }

    private fun getIssuerSignedData(decodedCredential: Map): Triple<Array, Map, Boolean> {
        if (decodedCredential.keys.contains(UnicodeString(DOCUMENTS))) {
            val documentElement = decodedCredential[DOCUMENTS][0] as Map
            val issuerSigned: DataItem = documentElement[ISSUER_SIGNED]
            val issuerAuth: Array = getIssuerAuth(issuerSigned)
            val issuerSignedNamespaces: Map = (issuerSigned[NAME_SPACES]) as Map
            return Triple(issuerAuth, issuerSignedNamespaces, false)
        }

        if (decodedCredential.keys.contains(UnicodeString(ISSUER_SIGNED))) {
            val issuerSigned: DataItem = decodedCredential[ISSUER_SIGNED]
            val issuerAuth: Array = getIssuerAuth(issuerSigned)
            val issuerSignedNamespaces: Map = (issuerSigned[NAME_SPACES]) as Map
            return Triple(issuerAuth, issuerSignedNamespaces, false)
        }

        if (decodedCredential.keys.contains(UnicodeString(ISSUER_AUTH)) &&
            decodedCredential.keys.contains(UnicodeString(NAME_SPACES))
        ) {
            val issuerAuth: Array = getIssuerAuth(decodedCredential)
            val issuerSignedNamespaces: Map = (decodedCredential[NAME_SPACES]) as Map
            return Triple(issuerAuth, issuerSignedNamespaces, true)
        }

        throw RuntimeException("Invalid issuerSigned structure in mDoc")
    }

    private fun validateMsoPayload(issuerAuth: Array, isLatest: Boolean) {
        try {
            val payload = CborDecoder.decode((issuerAuth[2] as ByteString).bytes)[0]
            if (isLatest && (payload.majorType != MajorType.BYTE_STRING || payload.tag != Tag(24))) {
                throw ValidationException("mso is not tagged", ERROR_CODE_INVALID_MSO)
            }

        } catch (exception: ValidationException) {
            throw exception
        } catch (exception: Exception) {
            logger.severe("Error while validating MSO - ${exception.message}")
            throw ValidationException("Invalid issuerAuth payload", ERROR_CODE_INVALID_MSO)
        }
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
