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
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_UNTRUSTED_ISSUER
import io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc.MdocStatusResults
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DIGEST_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DIGEST_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_NAME_SPACES_ENCODING
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MSO_NOT_TAGGED
import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc.MdocStatusListChecker
import io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc.MsoStatusListParseResult
import io.mosip.vercred.vcverifier.credentialverifier.validator.MsoMdocValidator
import io.mosip.vercred.vcverifier.credentialverifier.verifier.MsoMdocVerifier
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.data.ValidationStatus
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.signature.impl.CoseSignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils.getOrNull
import org.bouncycastle.asn1.x509.Extension
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.util.logging.Logger

internal const val DOCUMENTS = "documents"
internal const val X5C = 33L
internal const val COSE_ALG_HEADER_LABEL = 1L
/** COSE algorithm identifier for ES256 (RFC 9053). */
internal const val COSE_ALG_ES256 = -7L
/**
 * ES256 only: the COSE signature is checked by identity-credential's coseSign1CheckSignature,
 * which supports ES256 only. ES384 / ES512 / EdDSA are not supported yet.
 */
internal val SUPPORTED_COSE_ALGS = setOf(BigInteger.valueOf(COSE_ALG_ES256))
internal const val DOC_TYPE = "docType"
internal const val VERSION = "version"
internal const val DIGEST_ALGORITHM = "digestAlgorithm"
internal const val DIGEST_ID = "digestID"
internal const val RANDOM = "random"
internal const val ELEMENT_IDENTIFIER = "elementIdentifier"
internal const val ELEMENT_VALUE = "elementValue"
internal const val VALUE_DIGESTS = "valueDigests"
internal const val NAME_SPACES = "nameSpaces"
internal val KEY_USAGE_OID: String = Extension.keyUsage.id
internal val EXTENDED_KEY_USAGE_OID: String = Extension.extendedKeyUsage.id
/** Index of the digitalSignature bit in [java.security.cert.X509Certificate.getKeyUsage]. */
internal const val KEY_USAGE_DIGITAL_SIGNATURE = 0
internal const val VALIDITY_INFO = "validityInfo"
internal const val SIGNED = "signed"
internal const val EXPECTED_UPDATE = "expectedUpdate"
/** ISO 18013-5: digestID values must be less than 2^31. */
internal val DIGEST_ID_MAX_EXCLUSIVE: BigInteger = BigInteger.valueOf(1L shl 31)
internal const val MIN_DIGEST_SALT_BYTES = 16
/** MSO version: major 1, any minor (e.g. "1.0", "1.1"). */
internal val MSO_VERSION_PATTERN = Regex("""^1\.\d+$""")
internal val SUPPORTED_DIGEST_ALGORITHMS = setOf("SHA-256", "SHA-384", "SHA-512")
internal const val TAG_ENCODED_CBOR = 24L
private const val ISSUER_SIGNED = "issuerSigned"
private const val ISSUER_AUTH = "issuerAuth"

/**
 * Returns the MSO digestAlgorithm, or throws when it is missing or not SHA-256 / SHA-384 / SHA-512.
 * Shared by validation and verification, since verify() is public and can run without validate().
 */
internal fun requireSupportedDigestAlgorithm(mso: Map): String {
    val digestAlgorithm = (mso.getOrNull(DIGEST_ALGORITHM) as? UnicodeString)?.string
    if (digestAlgorithm == null || digestAlgorithm !in SUPPORTED_DIGEST_ALGORITHMS) {
        throw ValidationException(
            ERROR_MESSAGE_INVALID_DIGEST_ALGORITHM,
            ERROR_CODE_INVALID_DIGEST_ALGORITHM
        )
    }
    return digestAlgorithm
}

class MsoMdocVerifiableCredential(
    private val options: MsoMdocVerificationOptions = MsoMdocVerificationOptions(),
) : VerifiableCredential {

    private val logger = Logger.getLogger(MsoMdocVerifiableCredential::class.java.name)


    override fun validate(credential: String): ValidationStatus {
        try {
            MsoMdocValidator(options).validate(credential)
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
        return MsoMdocVerifier(options).verify(credential)
    }

    override fun checkStatus(
        credential: String,
        statusPurposes: List<String>?
    ): kotlin.collections.Map<String, CredentialStatusResult> {
        return try {
            val (_, credentialData, _) = parse(credential)
            val checker = MdocStatusListChecker()
            when (val parsed = checker.parseStatusPointer(credentialData.mso)) {
                is MsoStatusListParseResult.Absent -> emptyMap()
                is MsoStatusListParseResult.Malformed -> MdocStatusResults.supportedPurposes(
                    MdocStatusResults.failure(parsed.errorCode, parsed.errorMessage),
                    statusPurposes
                )
                is MsoStatusListParseResult.Found -> {
                    if (!issuerAuthSignatureBindsCertificate(credentialData)) {
                        logger.warning("mDoc issuerAuth is not verified; skipping status fetch")
                        return MdocStatusResults.supportedPurposes(
                            MdocStatusResults.failure(
                                STATUS_LIST_UNTRUSTED_ISSUER,
                                "mDoc issuerAuth signature is not verified; cannot authorize status signer"
                            ),
                            statusPurposes
                        )
                    }
                    checker.getStatuses(
                        credentialData.mso,
                        statusPurposes,
                        credentialData.issuerCertificate
                    )
                }
            }
        } catch (exception: Exception) {
            logger.warning("mDoc status check failed")
            MdocStatusResults.supportedPurposes(
                MdocStatusResults.failure(
                    StatusCheckErrorCode.STATUS_REFERENCE_MALFORMED.name,
                    "Failed to read MSO status pointer: ${exception.message}"
                ),
                statusPurposes
            )
        }
    }

    private fun issuerAuthSignatureBindsCertificate(credentialData: MsoMdocCredentialData): Boolean {
        val issuerAuth = credentialData.issuerSigned.issuerAuth ?: return false
        val certificate = credentialData.issuerCertificate ?: return false
        return try {
            CoseSignatureVerifierImpl().verify(
                certificate.publicKey,
                CborDataItemUtils.toByteArray(issuerAuth),
                null
            )
        } catch (_: Exception) {
            false
        }
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
     *
     * @param captureRawNameSpaces when true (verification), also captures the as-received
     * IssuerSignedItemBytes used for digest checks. Validation does not need them, so it skips
     * the extra byte scan.
     */
    fun parse(
        credential: String,
        captureRawNameSpaces: Boolean = true,
    ): Triple<Map, MsoMdocCredentialData, Boolean> {
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
        validateMsoPayload(issuerAuth)
        val mso = issuerAuth.extractMso()
        val issuerCertificate = extractDocumentSignerCertificate(issuerAuth)
        val docType = mso.get(UnicodeString(DOC_TYPE))
        val encodedNameSpaceItems = if (!captureRawNameSpaces) emptyMap() else try {
            MsoMdocNameSpacesRawBytes.extract(decodedData)
        } catch (exception: Exception) {
            logger.severe("Failed to capture as-received nameSpaces item bytes: ${exception.message}")
            throw ValidationException(
                ERROR_MESSAGE_INVALID_NAME_SPACES_ENCODING,
                ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
            )
        }

        return Triple(
            decodedCredential,
            MsoMdocCredentialData(
                docType,
                issuerSigned = MsoMdocCredentialData.IssuerSigned(
                    issuerAuth,
                    issuerSignedNamespaces,
                    encodedNameSpaceItems,
                ),
                mso,
                issuerCertificate,
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

    /** ISO 18013-5 §9.1.2.4: the payload is #6.24(bstr .cbor MobileSecurityObject) for every shape. */
    private fun validateMsoPayload(issuerAuth: Array) {
        try {
            val payload = CborDecoder.decode((issuerAuth[2] as ByteString).bytes)[0]
            if (payload.majorType != MajorType.BYTE_STRING || payload.tag != Tag(TAG_ENCODED_CBOR)) {
                throw ValidationException(ERROR_MESSAGE_MSO_NOT_TAGGED, ERROR_CODE_INVALID_MSO)
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
