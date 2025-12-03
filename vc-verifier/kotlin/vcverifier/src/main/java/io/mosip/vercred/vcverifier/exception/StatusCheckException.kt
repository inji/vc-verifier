package io.mosip.vercred.vcverifier.exception

class StatusCheckException(val errorMessage: String, val errorCode: StatusCheckErrorCode) : BaseUncheckedException(errorMessage)

enum class StatusCheckErrorCode {
    RANGE_ERROR,
    STATUS_VERIFICATION_ERROR,
    STATUS_RETRIEVAL_ERROR,
    INVALID_PURPOSE,
    INVALID_CREDENTIAL_STATUS,
    INVALID_INDEX,
    ENCODED_LIST_MISSING,
    BASE64_DECODE_FAILED,
    GZIP_DECOMPRESS_FAILED,
    UNKNOWN_ERROR
}