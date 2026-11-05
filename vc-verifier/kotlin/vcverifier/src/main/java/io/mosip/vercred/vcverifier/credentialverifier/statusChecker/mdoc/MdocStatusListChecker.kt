package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_FETCH_FAILED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_RESOLVER_REQUIRED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_REFERENCE_MALFORMED
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import io.mosip.vercred.vcverifier.data.MdocStatusResult
import io.mosip.vercred.vcverifier.data.MdocVerificationOptions
import io.mosip.vercred.vcverifier.data.MsoStatusPointer
import java.util.logging.Logger

/**
 * Orchestrates MSO status-list pointer parsing, injected resolution, CWT validation,
 * and IETF bit reading. Does not perform HTTP.
 */
class MdocStatusListChecker(
    private val pointerParser: MsoStatusPointerParser = MsoStatusPointerParser(),
    private val cwtValidator: MdocStatusListCwtValidator = MdocStatusListCwtValidator(),
    private val bitReader: MdocStatusBitReader = MdocStatusBitReader()
) {
    private val logger = Logger.getLogger(MdocStatusListChecker::class.java.name)

    fun checkStatusList(credential: String, options: MdocVerificationOptions): MdocStatusResult {
        val pointer = when (val parsed = parsePointer(credential)) {
            is MsoStatusPointerParseResult.Absent -> {
                return MdocStatusResult()
            }
            is MsoStatusPointerParseResult.Malformed -> {
                return MdocStatusResult(
                    errorCode = parsed.errorCode,
                    errorMessage = parsed.errorMessage
                )
            }
            is MsoStatusPointerParseResult.Found -> parsed.pointer
        }
        val resolver = options.statusListResolver
            ?: return errorResult(
                STATUS_LIST_RESOLVER_REQUIRED,
                "A StatusListResolver is required to read the mDoc status list",
                pointer
            )
        val cwtBytes = try {
            resolver.resolve(pointer.uri)
        } catch (exception: Exception) {
            logger.warning("Status list resolver failed for ${pointer.uri}: ${exception.message}")
            return errorResult(
                STATUS_LIST_FETCH_FAILED,
                "Failed to resolve status list at ${pointer.uri}: ${exception.message}",
                pointer
            )
        }
        return try {
            val validated = cwtValidator.validate(cwtBytes, pointer.uri)
            val status = bitReader.readStatus(validated.compressedLst, validated.bits, pointer.idx)
            MdocStatusResult(
                status = status,
                uri = pointer.uri,
                idx = pointer.idx,
                ttlSeconds = validated.ttlSeconds
            )
        } catch (exception: MdocStatusCheckException) {
            errorResult(exception.errorCode, exception.message, pointer)
        }
    }

    private fun parsePointer(credential: String): MsoStatusPointerParseResult {
        return try {
            val (_, credentialData, _) = MsoMdocVerifiableCredential().parse(credential)
            pointerParser.parse(credentialData.mso)
        } catch (exception: Exception) {
            MsoStatusPointerParseResult.Malformed(
                STATUS_REFERENCE_MALFORMED,
                "Failed to read MSO status pointer: ${exception.message}"
            )
        }
    }

    private fun errorResult(
        errorCode: String,
        errorMessage: String,
        pointer: MsoStatusPointer
    ): MdocStatusResult {
        return MdocStatusResult(
            errorCode = errorCode,
            errorMessage = errorMessage,
            uri = pointer.uri,
            idx = pointer.idx
        )
    }
}
