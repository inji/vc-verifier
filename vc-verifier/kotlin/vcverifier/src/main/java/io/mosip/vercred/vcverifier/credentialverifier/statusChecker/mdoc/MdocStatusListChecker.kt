package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.Map
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_FETCH_FAILED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_TYP
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_UNTRUSTED_ISSUER
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_REFERENCE_MALFORMED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PURPOSE_REVOCATION
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PURPOSE_SUSPENSION
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PURPOSE_VALID
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.data.MdocCredentialStatus
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import io.mosip.vercred.vcverifier.networkManager.HttpMethod.GET
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.networkManager.PublicHttpsDestination
import java.util.logging.Logger

/**
 * IETF Token Status List (ASL / CWT) checker for mDoc.
 * Fetches the status list CWT from `status.status_list.uri`, same as LDP HTTP GET.
 */
class MdocStatusListChecker(
    private val pointerParser: MsoStatusPointerParser = MsoStatusPointerParser(),
    private val cwtValidator: MdocStatusListCwtValidator = MdocStatusListCwtValidator(),
    private val bitReader: MdocStatusBitReader = MdocStatusBitReader()
) {
    private val logger = Logger.getLogger(MdocStatusListChecker::class.java.name)

    fun getStatuses(
        mso: Map,
        issuerAuth: Array?
    ): kotlin.collections.Map<String, CredentialStatusResult> {
        logger.info("Started mDoc status check.....")
        val pointer = when (val parsed = pointerParser.parse(mso)) {
            is MsoStatusPointerParseResult.Absent -> {
                logger.warning("No status list in MSO, skipping status check")
                return emptyMap()
            }
            is MsoStatusPointerParseResult.Malformed -> {
                logger.warning("MSO status pointer is malformed")
                return errorResult(parsed.errorCode, parsed.errorMessage)
            }
            is MsoStatusPointerParseResult.Found -> parsed.pointer
        }
        if (!PublicHttpsDestination.isAllowedUri(pointer.uri)) {
            logger.warning("MSO status list URI is not allowed")
            return errorResult(
                STATUS_REFERENCE_MALFORMED,
                "Status list URI is not allowed"
            )
        }
        val issuerCertificate = issuerAuth?.let { cwtValidator.issuerCertificateFrom(it) }
            ?: return errorResult(
                STATUS_LIST_UNTRUSTED_ISSUER,
                "mDoc issuerAuth x5chain is missing; cannot authorize status signer"
            )
        val cwtBytes = try {
            NetworkManagerClient.sendHTTPRequestBytes(
                pointer.uri,
                GET,
                mapOf("Accept" to STATUS_LIST_TYP)
            )
        } catch (exception: Exception) {
            logger.warning("Status list fetch failed")
            return errorResult(
                STATUS_LIST_FETCH_FAILED,
                "Failed to retrieve status list"
            )
        }
        return try {
            val validated = cwtValidator.validate(cwtBytes, pointer.uri, issuerCertificate)
            val status = bitReader.readStatus(validated.compressedLst, validated.bits, pointer.idx)
            logger.info("mDoc status check completed")
            mapStatus(status)
        } catch (exception: MdocStatusCheckException) {
            logger.warning("Status list check failed")
            errorResult(exception.errorCode, exception.message)
        }
    }

    private fun mapStatus(status: MdocCredentialStatus): kotlin.collections.Map<String, CredentialStatusResult> {
        return when (status) {
            MdocCredentialStatus.VALID ->
                mapOf(STATUS_PURPOSE_VALID to CredentialStatusResult(true, null))
            MdocCredentialStatus.INVALID -> {
                logger.warning("mDoc credential is revoked")
                mapOf(STATUS_PURPOSE_REVOCATION to CredentialStatusResult(false, null))
            }
            MdocCredentialStatus.SUSPENDED -> {
                logger.warning("mDoc credential is suspended")
                mapOf(STATUS_PURPOSE_SUSPENSION to CredentialStatusResult(false, null))
            }
        }
    }

    private fun errorResult(
        errorCode: String,
        errorMessage: String?
    ): kotlin.collections.Map<String, CredentialStatusResult> {
        return mapOf(
            STATUS_PURPOSE_VALID to CredentialStatusResult(
                false,
                StatusCheckException(errorMessage ?: errorCode, toErrorCode(errorCode))
            )
        )
    }

    private fun toErrorCode(code: String): StatusCheckErrorCode {
        return runCatching { StatusCheckErrorCode.valueOf(code) }
            .getOrDefault(StatusCheckErrorCode.UNKNOWN_ERROR)
    }
}
