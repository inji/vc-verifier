package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.MSO_STATUS_IDX_KEY
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.MSO_STATUS_KEY
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.MSO_STATUS_LIST_KEY
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.MSO_STATUS_URI_KEY
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_FETCH_FAILED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_MALFORMED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_TYP
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_UNTRUSTED_ISSUER
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_REFERENCE_MALFORMED
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.data.MdocCredentialStatus
import io.mosip.vercred.vcverifier.data.MsoStatusPointer
import io.mosip.vercred.vcverifier.networkManager.HttpMethod.GET
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils.getOrNull
import java.security.cert.X509Certificate
import java.util.logging.Logger

/**
 * IETF Token Status List (ASL / CWT) checker for mDoc.
 * Fetches the status list CWT from `status.status_list.uri`, same as LDP HTTP GET.
 */
class MdocStatusListChecker(
    private val cwtValidator: MdocStatusListCwtValidator = MdocStatusListCwtValidator(),
    private val bitReader: MdocStatusBitReader = MdocStatusBitReader()
) {
    private val logger = Logger.getLogger(MdocStatusListChecker::class.java.name)

    fun getStatuses(
        mso: Map,
        statusPurposes: List<String>? = null,
        issuerCertificate: X509Certificate? = null
    ): kotlin.collections.Map<String, CredentialStatusResult> {
        val results = readStatuses(mso, issuerCertificate)
        val filteredStatus = MdocStatusResults.filterByRequestedPurposes(results, statusPurposes)
        if (filteredStatus.isEmpty() && results.isNotEmpty() && !statusPurposes.isNullOrEmpty()) {
            logger.warning("No matching mDoc status for purposes: $statusPurposes")
        }
        return filteredStatus
    }

    private fun readStatuses(
        mso: Map,
        issuerCertificate: X509Certificate?
    ): kotlin.collections.Map<String, CredentialStatusResult> {
        logger.info("Started mDoc status check.....")
        val pointer = when (val parsed = parseStatusPointer(mso)) {
            is MsoStatusListParseResult.Absent -> {
                logger.warning("No status list in MSO, skipping status check")
                return emptyMap()
            }
            is MsoStatusListParseResult.Malformed -> {
                logger.warning("MSO status list is malformed")
                return MdocStatusResults.failure(parsed.errorCode, parsed.errorMessage)
            }
            is MsoStatusListParseResult.Found -> parsed.pointer
        }
        val dsCertificate = issuerCertificate
            ?: return MdocStatusResults.failure(
                STATUS_LIST_UNTRUSTED_ISSUER,
                "mDoc issuerAuth x5chain is missing; cannot authorize status signer"
            )
        val cwtBytes = try {
            NetworkManagerClient.sendHTTPRequestForBytes(
                pointer.uri,
                GET,
                mapOf("Accept" to STATUS_LIST_TYP)
            )
        } catch (exception: Exception) {
            logger.warning("Status list fetch failed")
            return MdocStatusResults.failure(
                STATUS_LIST_FETCH_FAILED,
                "Failed to retrieve status list"
            )
        }
        return try {
            val validated = cwtValidator.validate(cwtBytes, pointer.uri, dsCertificate)
            val status = bitReader.readStatus(validated.compressedLst, validated.bits, pointer.idx)
            logger.info("mDoc status check completed")
            when (status) {
                MdocCredentialStatus.INVALID -> logger.warning("mDoc credential is revoked")
                MdocCredentialStatus.SUSPENDED -> logger.warning("mDoc credential is suspended")
                MdocCredentialStatus.VALID -> Unit
            }
            MdocStatusResults.statusResult(status, validated.bits)
        } catch (exception: MdocStatusCheckException) {
            logger.warning("Status list check failed")
            MdocStatusResults.failure(exception.errorCode, exception.message)
        } catch (overflow: StackOverflowError) {
            logger.warning("Status list check failed")
            MdocStatusResults.failure(
                STATUS_LIST_MALFORMED,
                "Status list CWT is not valid CBOR: nested structure too deep"
            )
        }
    }

    /**
     * Reads `status.status_list {uri, idx}` from a verified MSO.
     * Missing `status` / `status_list` is not an error — status checking is skipped.
     */
    internal fun parseStatusPointer(mso: Map): MsoStatusListParseResult {
        val statusItem = mso.getOrNull(MSO_STATUS_KEY) ?: return MsoStatusListParseResult.Absent
        if (statusItem !is Map) {
            return malformed("MSO status is present but is not a map")
        }
        val statusListItem = statusItem.getOrNull(MSO_STATUS_LIST_KEY)
            ?: return MsoStatusListParseResult.Absent
        if (statusListItem !is Map) {
            return malformed("MSO status.status_list is present but is not a map")
        }
        val uriItem = statusListItem.getOrNull(MSO_STATUS_URI_KEY)
        val idxItem = statusListItem.getOrNull(MSO_STATUS_IDX_KEY)
        if (uriItem == null || idxItem == null) {
            return malformed("MSO status.status_list is missing uri or idx")
        }
        if (uriItem !is UnicodeString || uriItem.string.isNullOrBlank()) {
            return malformed("MSO status.status_list.uri must be a non-empty text string")
        }
        if (idxItem !is UnsignedInteger) {
            return malformed("MSO status.status_list.idx must be an unsigned integer")
        }
        val idx = idxItem.value.toLong()
        if (idx < 0) {
            return malformed("MSO status.status_list.idx must be a non-negative unsigned integer")
        }
        return MsoStatusListParseResult.Found(MsoStatusPointer(uriItem.string, idx))
    }

    private fun malformed(message: String) = MsoStatusListParseResult.Malformed(
        STATUS_REFERENCE_MALFORMED,
        message
    )
}

internal sealed class MsoStatusListParseResult {
    object Absent : MsoStatusListParseResult()
    data class Found(val pointer: MsoStatusPointer) : MsoStatusListParseResult()
    data class Malformed(val errorCode: String, val errorMessage: String) : MsoStatusListParseResult()
}
