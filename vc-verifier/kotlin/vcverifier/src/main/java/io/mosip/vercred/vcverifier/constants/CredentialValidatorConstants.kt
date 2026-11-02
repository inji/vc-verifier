package io.mosip.vercred.vcverifier.constants

object CredentialValidatorConstants {

    const val CREDENTIALS_CONTEXT_V1_URL = "https://www.w3.org/2018/credentials/v1"
    const val CREDENTIALS_CONTEXT_V2_URL = "https://www.w3.org/ns/credentials/v2"
    const val VERIFIABLE_CREDENTIAL = "VerifiableCredential"

    const val ISSUER = "issuer"
    const val CREDENTIAL_SUBJECT = "credentialSubject"
    const val HOLDER = "holder"
    const val PROOF = "proof"
    const val TYPE = "type"
    const val CONTEXT = "@context"
    const val ISSUANCE_DATE = "issuanceDate"
    const val EXPIRATION_DATE = "expirationDate"
    const val ID = "id"
    const val JWS = "jws"
    const val VALID_FROM = "validFrom"
    const val VALID_UNTIL = "validUntil"
    const val CREDENTIAL_STATUS = "credentialStatus"
    const val EVIDENCE = "evidence"
    const val TERMS_OF_USE = "termsOfUse"
    const val REFRESH_SERVICE = "refreshService"
    const val CREDENTIAL_SCHEMA = "credentialSchema"
    const val NAME = "name"
    const val DESCRIPTION = "description"
    const val LANGUAGE = "language"
    const val VALUE = "value"

    const val ALGORITHM = "Algorithm"

    private const val VALIDATION_ERROR = "Validation Error: "
    const val ERROR_MISSING_REQUIRED_FIELDS = "${VALIDATION_ERROR}Missing required field: "


    const val ERROR_CODE_EMPTY_VC_JSON = "ERR_EMPTY_VC"
    const val ERROR_CODE_MISSING = "ERR_MISSING_"
    const val ERROR_CODE_INVALID = "ERR_INVALID_"
    const val ERROR_CODE_GENERIC = "ERR_GENERIC"

    const val ERROR_MESSAGE_CONTEXT_FIRST_LINE = "${VALIDATION_ERROR}$CREDENTIALS_CONTEXT_V1_URL or $CREDENTIALS_CONTEXT_V2_URL needs to be first in the list of contexts."
    const val ERROR_MESSAGE_EMPTY_VC_JSON = "${VALIDATION_ERROR}Input VC JSON string is null or empty."
    const val ERROR_MESSAGE_TYPE_VERIFIABLE_CREDENTIAL = "${VALIDATION_ERROR}type must include `VerifiableCredential`."
    const val ERROR_INVALID_URI = "${VALIDATION_ERROR}Invalid URI: "
    const val ERROR_INVALID_FIELD = "${VALIDATION_ERROR}Invalid Field: "
    const val EXCEPTION_DURING_VALIDATION = "Exception during Validation: "
    const val ERROR_MESSAGE_ALGORITHM_NOT_SUPPORTED = "${VALIDATION_ERROR}Algorithm used in the proof is not matching with supported algorithms"
    const val ERROR_MESSAGE_PROOF_TYPE_NOT_SUPPORTED = "${VALIDATION_ERROR}Proof Type is not matching with supported types"
    const val ERROR_CREDENTIAL_SUBJECT_NON_NULL_OBJECT = "$CREDENTIAL_SUBJECT must be a non-null object or array of objects."
    const val ERROR_ISSUANCE_DATE_INVALID = "${VALIDATION_ERROR}issuanceDate is not valid."
    const val ERROR_EXPIRATION_DATE_INVALID = "${VALIDATION_ERROR}expirationDate is not valid."
    const val ERROR_VALID_FROM_INVALID = "${VALIDATION_ERROR}validFrom is not valid."
    const val ERROR_VALID_UNTIL_INVALID = "${VALIDATION_ERROR}validUntil is not valid."

    const val ERROR_MESSAGE_EMPTY_VC_CWT="${VALIDATION_ERROR}Input VC CWT string is null or empty."

    const val ERROR_MESSAGE_INVALID_HEX_VC_CWT="${VALIDATION_ERROR}Invalid hexadecimal format"


    const val ERROR_CODE_VC_EXPIRED = "ERR_VC_EXPIRED"
    const val ERROR_MESSAGE_VC_EXPIRED = "VC is expired"

    const val ERROR_CODE_CURRENT_DATE_BEFORE_ISSUANCE_DATE = "ERR_ISSUANCE_DATE_IS_FUTURE_DATE"
    const val ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE = "${VALIDATION_ERROR}The current date time is before the issuanceDate"

    const val ERROR_CODE_CURRENT_DATE_BEFORE_VALID_FROM = "ERR_VALID_FROM_IS_FUTURE_DATE"
    const val ERROR_CURRENT_DATE_BEFORE_VALID_FROM = "${VALIDATION_ERROR}The current date time is before the validFrom Date"

    const val ERROR_CODE_CURRENT_DATE_BEFORE_PROCESSING_DATE = "ERR_PROCESSING_DATE_IS_FUTURE_DATE"
    const val ERROR_CURRENT_DATE_BEFORE_PROCESSING_DATE = "${VALIDATION_ERROR}The current date time is before the not before(nbf) claim Date"

    const val ERROR_MESSAGE_NAME = "${VALIDATION_ERROR}name should be string or array of Language Object"
    const val ERROR_MESSAGE_DESCRIPTION = "${VALIDATION_ERROR}description should be string or array of Language Object"

    const val ERROR_MESSAGE_INVALID_SIGNED_MSO = "invalid validityInfo->signed in the MSO of the credential"
    const val ERROR_MESSAGE_INVALID_EXPECTED_UPDATE_MSO = "invalid validityInfo->expectedUpdate in the MSO of the credential"
    const val ERROR_CODE_INVALID_MSO = "${ERROR_CODE_INVALID}MSO"
    const val ERROR_CODE_INVALID_VALIDITY_INFO_MSO = "${ERROR_CODE_INVALID}VALIDITY_INFO_MSO"

    const val ERROR_MESSAGE_INVALID_VALID_FROM_MSO = "invalid validFrom in the MSO of the credential"
    const val ERROR_CODE_INVALID_VALID_FROM_MSO = "${ERROR_CODE_INVALID}VALID_FROM_MSO"

    const val ERROR_MESSAGE_INVALID_VALID_UNTIL_MSO = "invalid validUntil in the MSO of the credential"
    const val ERROR_CODE_INVALID_VALID_UNTIL_MSO = "${ERROR_CODE_INVALID}VALID_UNTIL_MSO"

    const val ERROR_MESSAGE_INVALID_DATE_MSO = "invalid validUntil / validFrom in the MSO of the credential"
    const val ERROR_CODE_INVALID_DATE_MSO = "${ERROR_CODE_INVALID}DATE_MSO"
    const val ERROR_CODE_INVALID_VALIDITY_INFO = "${ERROR_CODE_INVALID}VALIDITY_INFO"

    const val ERROR_CODE_INVALID_DS_CERT_VALIDITY = "${ERROR_CODE_INVALID}DS_CERT_VALIDITY"
    const val ERROR_MESSAGE_INVALID_DS_CERT_VALIDITY =
        "DS certificate is outside its validity period"

    const val ERROR_CODE_INVALID_DS_CERT_EKU = "${ERROR_CODE_INVALID}DS_CERT_EKU"
    const val ERROR_MESSAGE_INVALID_DS_CERT_EKU =
        "DS certificate is missing the required mDL extended key usage"

    const val ERROR_CODE_INVALID_DS_CERT_KEY_USAGE = "${ERROR_CODE_INVALID}DS_CERT_KEY_USAGE"
    const val ERROR_MESSAGE_INVALID_DS_CERT_KEY_USAGE =
        "DS certificate key usage must include digitalSignature"

    const val ERROR_CODE_INVALID_SIGNED_OUTSIDE_DS_CERT = "${ERROR_CODE_INVALID}SIGNED_OUTSIDE_DS_CERT"
    const val ERROR_MESSAGE_INVALID_SIGNED_OUTSIDE_DS_CERT =
        "MSO signed date is outside the DS certificate validity period"

    const val ERROR_CODE_INVALID_ISSUING_COUNTRY = "${ERROR_CODE_INVALID}ISSUING_COUNTRY"
    const val ERROR_MESSAGE_INVALID_ISSUING_COUNTRY =
        "issuing_country does not match the DS certificate countryName"

    const val ERROR_CODE_INVALID_ISSUING_JURISDICTION = "${ERROR_CODE_INVALID}ISSUING_JURISDICTION"
    const val ERROR_MESSAGE_INVALID_ISSUING_JURISDICTION =
        "issuing_jurisdiction does not match the DS certificate stateOrProvinceName"

    const val ERROR_CODE_INVALID_VALUE_DIGESTS = "${ERROR_CODE_INVALID}VALUE_DIGESTS"
    const val ERROR_MESSAGE_INVALID_VALUE_DIGESTS =
        "valueDigests verification failed - mismatch or missing digest for a received record"

    const val ERROR_CODE_INVALID_DIGEST_ID = "${ERROR_CODE_INVALID}DIGEST_ID"
    const val ERROR_MESSAGE_INVALID_DIGEST_ID =
        "Duplicate digestID found in a namespace"
    const val ERROR_MESSAGE_DIGEST_ID_OUT_OF_RANGE =
        "digestID must be an unsigned integer less than 2^31"

    const val ERROR_CODE_INVALID_DIGEST_SALT = "${ERROR_CODE_INVALID}DIGEST_SALT"
    const val ERROR_MESSAGE_INVALID_DIGEST_SALT =
        "IssuerSignedItem random (salt) must be at least 16 bytes"

    const val ERROR_CODE_INVALID_DIGEST_ALGORITHM = "${ERROR_CODE_INVALID}DIGEST_ALGORITHM"
    const val ERROR_MESSAGE_INVALID_DIGEST_ALGORITHM =
        "digestAlgorithm must be SHA-256, SHA-384 or SHA-512"

    const val ERROR_CODE_INVALID_MSO_VERSION = "${ERROR_CODE_INVALID}MSO_VERSION"
    const val ERROR_MESSAGE_INVALID_MSO_VERSION = "MSO version major number must be 1"

    const val ERROR_CODE_MISSING_ALG = "${ERROR_CODE_MISSING}ALG"
    const val ERROR_MESSAGE_MISSING_ALG = "alg is missing from the COSE protected header"

    const val ERROR_CODE_INVALID_ALG = "${ERROR_CODE_INVALID}ALG"
    const val ERROR_MESSAGE_INVALID_MSO_ALG = "alg must be ES256 (-7), ES384 (-35) or ES512 (-36)"

    const val ERROR_CODE_INVALID_MDL_ELEMENT = "${ERROR_CODE_INVALID}MDL_ELEMENT"
    const val ERROR_MESSAGE_INVALID_MDL_ELEMENT_TYPE =
        "mDL data element has an invalid type"
    const val ERROR_MESSAGE_INVALID_MDL_ELEMENT_TEXT =
        "mDL text element must be Latin-1 and at most 150 characters"
    const val ERROR_MESSAGE_INVALID_DRIVING_PRIVILEGES =
        "driving_privileges structure is invalid"
    const val ERROR_MESSAGE_MISSING_MDL_MANDATORY_ELEMENT =
        "Mandatory mDL data element is missing"
    const val ERROR_MESSAGE_INVALID_MDL_AGE =
        "age_over_NN / age_in_years is inconsistent with birth_date"

    const val ERROR_CODE_INVALID_ISSUE_DATE = "${ERROR_CODE_INVALID}ISSUE_DATE"
    const val ERROR_MESSAGE_INVALID_ISSUE_DATE =
        "issue_date must not be after validFrom"
    const val ERROR_MESSAGE_INVALID_ISSUE_DATE_FORMAT =
        "issue_date must be a valid full date (YYYY-MM-DD)"

    const val ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM = "${ERROR_CODE_INVALID}ISSUER_SIGNED_ITEM"
    const val ERROR_MESSAGE_INVALID_ISSUER_SIGNED_ITEM =
        "Each nameSpaces record must be a tag-24 byte string"

    const val ERROR_CODE_INVALID_MSO_DATE_FORMAT = "${ERROR_CODE_INVALID}MSO_DATE_FORMAT"
    const val ERROR_MESSAGE_INVALID_MSO_DATE_FORMAT =
        "validityInfo dates must have no fractional seconds and end in Z"

    const val ERROR_CODE_INVALID_JWT_FORMAT = "${ERROR_CODE_INVALID}JWT_FORMAT"
    const val ERROR_MESSAGE_INVALID_JWT_FORMAT = "${VALIDATION_ERROR}Invalid JWT format"

    const val ERROR_CODE_MISSING_VCT = "${ERROR_CODE_MISSING}VCT"
    const val ERROR_MESSAGE_MISSING_VCT = "${VALIDATION_ERROR}Missing or empty 'vct' in JWT payload"

    const val ERROR_CODE_INVALID_VCT_URI = "${ERROR_CODE_INVALID}VCT_URI"
    const val ERROR_MESSAGE_INVALID_VCT_URI = "${VALIDATION_ERROR}'vct' must be a valid URI when it contains ':'"

    const val ERROR_CODE_INVALID_DISCLOSURE_FORMAT = "${ERROR_CODE_INVALID}DISCLOSURE_FORMAT"
    const val ERROR_MESSAGE_INVALID_DISCLOSURE_FORMAT = "${VALIDATION_ERROR}Disclosure is not a valid base64url-encoded JSON array"

    const val ERROR_CODE_INVALID_DISCLOSURE_STRUCTURE = "${ERROR_CODE_INVALID}DISCLOSURE_STRUCTURE"
    const val ERROR_MESSAGE_INVALID_DISCLOSURE_STRUCTURE = "${VALIDATION_ERROR}Disclosure must be a 2- or 3-element JSON array"

    const val ERROR_CODE_INVALID_DISCLOSURE_CLAIM_NAME = "${ERROR_CODE_INVALID}DISCLOSURE_CLAIM_NAME"
    const val ERROR_MESSAGE_INVALID_DISCLOSURE_CLAIM_NAME = "${VALIDATION_ERROR}Disclosure has invalid or reserved claim name (starts with underscore)"

    const val ERROR_CODE_INVALID_KB_JWT_FORMAT = "${ERROR_CODE_INVALID}KB_JWT_FORMAT"
    const val ERROR_MESSAGE_INVALID_KB_JWT_FORMAT = "${VALIDATION_ERROR}Invalid Key Binding JWT format"

    const val ERROR_CODE_MISSING_KB_JWT = "${ERROR_CODE_MISSING}KB_JWT"
    const val ERROR_MESSAGE_MISSING_KB_JWT = "Missing Key Binding JWT"

    
    val ALGORITHMS_SUPPORTED = listOf(
        "PS256",
        "RS256",
        "EdDSA",
        "ES256",
        "ES256K"
    )

    val PROOF_TYPES_SUPPORTED = listOf(
        "RsaSignature2018",
        "Ed25519Signature2018",
        "Ed25519Signature2020",
        "EcdsaSecp256k1Signature2019",
        "EcdsaSecp256r1Signature2019",
        "DataIntegrityProof",
    )
}
