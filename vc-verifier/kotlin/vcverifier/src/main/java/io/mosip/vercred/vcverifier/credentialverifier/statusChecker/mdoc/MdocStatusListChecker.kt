package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.Map
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_FETCH_FAILED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_TYP
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_UNTRUSTED_ISSUER
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.data.MdocCredentialStatus
import io.mosip.vercred.vcverifier.credentialverifier.validator.MsoStatusListValidationResult
import io.mosip.vercred.vcverifier.credentialverifier.validator.MsoStatusListValidator
import io.mosip.vercred.vcverifier.networkManager.HttpMethod.GET
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import java.security.cert.X509Certificate
import java.util.logging.Logger

/**
 * IETF Token Status List (ASL / CWT) checker for mDoc.
 * Fetches the status list CWT from `status.status_list.uri`, same as LDP HTTP GET.
 */
class MdocStatusListChecker(
    private val statusListValidator: MsoStatusListValidator = MsoStatusListValidator(),
    private val cwtValidator: MdocStatusListCwtValidator = MdocStatusListCwtValidator(),
    private val bitReader: MdocStatusBitReader = MdocStatusBitReader()
) {
    private val logger = Logger.getLogger(MdocStatusListChecker::class.java.name)

    fun getStatuses(
        mso: Map,
        issuerAuth: Array?,
        statusPurposes: List<String>? = null,
        verifiedIssuerCertificate: X509Certificate? = null
    ): kotlin.collections.Map<String, CredentialStatusResult> {
        val results = readStatuses(mso, issuerAuth, verifiedIssuerCertificate)
        val supportedStatus = MdocStatusResults.supportedPurposes(results, statusPurposes)
        if (supportedStatus.isEmpty() && results.isNotEmpty() && !statusPurposes.isNullOrEmpty()) {
            logger.warning("No matching mDoc status for purposes: $statusPurposes")
        }
        return supportedStatus
    }

    private fun readStatuses(
        mso: Map,
        issuerAuth: Array?,
        verifiedIssuerCertificate: X509Certificate?
    ): kotlin.collections.Map<String, CredentialStatusResult> {
        logger.info("Started mDoc status check.....")
        val pointer = when (val validated = statusListValidator.validate(mso)) {
            is MsoStatusListValidationResult.Absent -> {
                logger.warning("No status list in MSO, skipping status check")
                return emptyMap()
            }
            is MsoStatusListValidationResult.Malformed -> {
                logger.warning("MSO status list is malformed")
                return MdocStatusResults.failure(validated.errorCode, validated.errorMessage)
            }
            is MsoStatusListValidationResult.Found -> validated.pointer
        }
        val issuerCertificate = verifiedIssuerCertificate
            ?: issuerAuth?.let { cwtValidator.issuerCertificateFrom(it) }
            ?: return MdocStatusResults.failure(
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
            return MdocStatusResults.failure(
                STATUS_LIST_FETCH_FAILED,
                "Failed to retrieve status list"
            )
        }
        return try {
            val validated = cwtValidator.validate(cwtBytes, pointer.uri, issuerCertificate)
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
        }
    }
}
