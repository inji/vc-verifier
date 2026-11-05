package io.mosip.vercred.vcverifier.data

enum class MdocCredentialStatus { VALID, INVALID, SUSPENDED }

fun interface StatusListResolver {
    fun resolve(uri: String): ByteArray
}

data class MdocVerificationOptions(
    val statusListResolver: StatusListResolver? = null
)

data class MsoStatusPointer(val uri: String, val idx: Long)

data class MdocStatusResult(
    val status: MdocCredentialStatus? = null,
    val errorCode: String? = null,
    val errorMessage: String? = null,
    val uri: String? = null,
    val idx: Long? = null,
    val ttlSeconds: Long? = null
)

data class MdocVerificationResult(
    val verificationResult: VerificationResult,
    val statusResult: MdocStatusResult? = null
)
