package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import com.fasterxml.jackson.databind.ObjectMapper
import foundation.identity.jsonld.JsonLDObject
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TYPE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_UNTIL
import io.mosip.vercred.vcverifier.constants.StatusCheckerConstants.BITSTRING_STATUS_LIST
import io.mosip.vercred.vcverifier.constants.StatusCheckerConstants.BITSTRING_STATUS_LIST_ENTRY
import io.mosip.vercred.vcverifier.constants.StatusCheckerConstants.ENCODED_LIST
import io.mosip.vercred.vcverifier.constants.StatusCheckerConstants.STATUS_LIST_CREDENTIAL
import io.mosip.vercred.vcverifier.constants.StatusCheckerConstants.STATUS_LIST_INDEX
import io.mosip.vercred.vcverifier.constants.StatusCheckerConstants.STATUS_MESSAGE
import io.mosip.vercred.vcverifier.constants.StatusCheckerConstants.STATUS_PURPOSE
import io.mosip.vercred.vcverifier.constants.StatusCheckerConstants.STATUS_SIZE
import io.mosip.vercred.vcverifier.credentialverifier.types.LdpVerifiableCredential
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.BASE64_DECODE_FAILED
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.ENCODED_LIST_MISSING
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.GZIP_DECOMPRESS_FAILED
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.INVALID_CREDENTIAL_STATUS
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.INVALID_INDEX
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.INVALID_PURPOSE
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.RANGE_ERROR
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.STATUS_RETRIEVAL_ERROR
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.STATUS_VERIFICATION_ERROR
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import io.mosip.vercred.vcverifier.networkManager.HttpMethod.GET
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import io.mosip.vercred.vcverifier.utils.DateUtils
import io.mosip.vercred.vcverifier.utils.Util.isValidUri
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.logging.Logger
import java.util.zip.GZIPInputStream


/**
 * Generic StatusList2021 checker for LDP VCs.
 * Supports optional filtering by known statusPurposes.
 */
class LdpStatusChecker() {

    private val logger = Logger.getLogger(LdpStatusChecker::class.java.name)

    private val verifier = LdpVerifiableCredential()
    private val minimumNumberOfEntries = 131072
    private val validStatusValue = 0
    private val defaultStatusSize = 1
    private val mapper = ObjectMapper()

    /**
     * Checks one or more credentialStatus entries from a VC.
     *
     * @param credential The input VC JSON string.
     * @param statusPurposes Optional list of supported status purposes (e.g., ["revocation", "suspension"]).
     *                       If null, all credentialStatus entries will be checked.
     */
    fun getStatuses(
        credential: String,
        statusPurposes: List<String>? = null
    ): Map<String, CredentialStatusResult> {
        logger.info("Started status check")

        val jsonLD = JsonLDObject.fromJson(credential)
        val statusField = jsonLD.jsonObject["credentialStatus"]
        if (statusField == null) {
            logger.warning("No credentialStatus field present in the VC")
            return emptyMap()
        }

        val entries = when (statusField) {
            is List<*> -> statusField.filterIsInstance<Map<*, *>>()
            is Map<*, *> -> listOf(statusField)
            else -> emptyList()
        }

        if (entries.isEmpty()) {
            throw StatusCheckException(
                "No valid credentialStatus entries found",
                INVALID_CREDENTIAL_STATUS
            )
        }

        // Filter entries based on supported purposes (if provided)
        val filteredEntries = if (statusPurposes.isNullOrEmpty()) {
            entries
        } else {
            val supported = statusPurposes.map { it.lowercase() }
            entries.filter {
                val purpose = it[STATUS_PURPOSE]?.toString()?.lowercase()
                purpose in supported
            }
        }


        if (filteredEntries.isEmpty()) {
            logger.warning("No matching credentialStatus entries found for purposes: $statusPurposes")
            return emptyMap()
        }

        val results = mutableMapOf<String, CredentialStatusResult>()
        filteredEntries.forEach { entry ->
            var purpose = ""
            try {
                purpose =
                    entry[STATUS_PURPOSE]?.toString()?.lowercase() ?: throw StatusCheckException(
                        "$STATUS_PURPOSE Invalid",
                        errorCode = INVALID_PURPOSE
                    )

                val credentialStatusResult: Map<String, CredentialStatusResult> = checkStatusEntry(entry, purpose)
                results.putAll(credentialStatusResult)
            } catch (exception: StatusCheckException) {
                logger.warning("Status check failed for purpose '$purpose': ${exception.message}")
                // Add a failure entry (optional, to keep track of skipped purposes)
                results[purpose] = CredentialStatusResult(false, exception)
            }
        }
        return results
    }

    /**
     * Checks a single credentialStatus entry for its purpose.
     */
    private fun checkStatusEntry(entry: Map<*, *>, purpose: String): Map<String, CredentialStatusResult> {
        validateCredentialStatusEntry(entry)
        val statusListVC = fetchAndValidateStatusListVC(entry, purpose)
        return computeStatusResult(entry, statusListVC, purpose)
    }

    private fun fetchAndValidateStatusListVC(entry: Map<*, *>, purpose: String): JsonLDObject {
        val statusListCredentialUrl = entry[STATUS_LIST_CREDENTIAL].toString()
        val statusListVCMap: Map<*, *>

        try {
            statusListVCMap = sendHTTPRequest(statusListCredentialUrl, GET)
                ?: throw StatusCheckException(
                    "Failed to retrieve status list VC",
                    STATUS_RETRIEVAL_ERROR
                )
        } catch (e: Exception) {
            throw StatusCheckException(
                "Retrieval of the status list failed: ${e.message}",
                STATUS_RETRIEVAL_ERROR
            )
        }

        val statusListVCString = mapper.writeValueAsString(statusListVCMap)
        val statusListVC = JsonLDObject.fromJson(statusListVCString)

        if (!verifier.verify(statusListVCString)) {
            throw StatusCheckException(
                "Invalid signature on status list VC",
                STATUS_VERIFICATION_ERROR
            )
        }


        val credentialSubject = statusListVC.jsonObject[CREDENTIAL_SUBJECT] as? Map<*, *>
            ?: throw StatusCheckException(
                "Missing '${CREDENTIAL_SUBJECT}'",
                STATUS_VERIFICATION_ERROR
            )

        val validFromStr = credentialSubject[VALID_FROM] as? String
        val validUntilStr = credentialSubject[VALID_UNTIL] as? String
        val nowMillis = System.currentTimeMillis()

        if (!validFromStr.isNullOrEmpty()) {
            val validFromMillis = DateUtils.parseDate(validFromStr)?.time
                ?: throw StatusCheckException(
                    "Invalid $VALID_FROM format: $validFromStr",
                    STATUS_VERIFICATION_ERROR
                )

            if (nowMillis < validFromMillis) {
                throw StatusCheckException(
                    "Status list VC is not yet valid ($VALID_FROM=$validFromStr)",
                    STATUS_VERIFICATION_ERROR
                )
            }
        }

        if (!validUntilStr.isNullOrEmpty()) {
            val validUntilMillis = DateUtils.parseDate(validUntilStr)?.time
                ?: throw StatusCheckException(
                    "Invalid $VALID_UNTIL format: $validUntilStr",
                    STATUS_VERIFICATION_ERROR
                )

            if (nowMillis > validUntilMillis) {
                throw StatusCheckException(
                    "Status list VC has expired ($VALID_UNTIL=$validUntilStr)",
                    STATUS_VERIFICATION_ERROR
                )
            }
        }

        val statusListType = credentialSubject[TYPE]?.toString()
            ?: throw StatusCheckException(
                "Missing '$TYPE' in status list credential",
                STATUS_VERIFICATION_ERROR
            )

        if (statusListType != BITSTRING_STATUS_LIST) {
            throw StatusCheckException(
                "Invalid ${CREDENTIAL_SUBJECT}.type: Expected '$BITSTRING_STATUS_LIST', found '$statusListType'",
                STATUS_VERIFICATION_ERROR
            )
        }

        if (credentialSubject[STATUS_PURPOSE]?.toString()?.lowercase() != purpose) {
            throw StatusCheckException(
                "Status list VC purpose mismatch. Expected '$purpose', found '${credentialSubject[STATUS_PURPOSE]}'",
                STATUS_VERIFICATION_ERROR
            )
        }

        return statusListVC
    }

    private fun computeStatusResult(
        entry: Map<*, *>,
        statusListVC: JsonLDObject,
        purpose: String
    ): Map<String, CredentialStatusResult> {
        val credentialSubject = statusListVC.jsonObject[CREDENTIAL_SUBJECT] as Map<*, *>

        val encodedList = credentialSubject[ENCODED_LIST] as? String
            ?: throw StatusCheckException(
                "Missing '$ENCODED_LIST'",
                ENCODED_LIST_MISSING
            )

        val statusSize =
            credentialSubject[STATUS_SIZE]?.toString()?.toIntOrNull() ?: defaultStatusSize
        if (!isValid(statusSize)) {
            throw StatusCheckException(
                "Invalid '$STATUS_SIZE': must be > 0 if present.",
                STATUS_VERIFICATION_ERROR
            )
        }

        if (isStatusMessageAvailable(statusSize)) {
            val statusMessage = entry[STATUS_MESSAGE] as? Map<*, *>
                ?: throw StatusCheckException(
                    "Missing '$STATUS_MESSAGE' for $STATUS_SIZE=$statusSize",
                    STATUS_VERIFICATION_ERROR
                )
            logger.info("Status message for purpose '$purpose': $statusMessage")

            val expectedStatusCount = 1.shl(statusSize)
            if (statusMessage.size != expectedStatusCount) {
                throw StatusCheckException(
                    "$STATUS_MESSAGE count mismatch. Expected $expectedStatusCount entries for statusSize=$statusSize, found ${statusMessage.size}",
                    STATUS_VERIFICATION_ERROR
                )
            }
        }

        val statusListIndex = entry[STATUS_LIST_INDEX].toString().toInt()
        val decodedBitSet = decodeEncodedList(encodedList)
        val totalBits = decodedBitSet.size * 8
        if (totalBits < minimumNumberOfEntries * statusSize) {
            logger.warning("Decoded bitstring shorter than required herd privacy length")
        }

        val bitPosition = statusListIndex * statusSize
        if (bitPosition >= totalBits) {
            throw StatusCheckException(
                "Bit position $bitPosition out of range",
                RANGE_ERROR
            )
        }

        val statusValue = readBits(bitPosition, decodedBitSet, statusSize)
        logger.info("Status value for purpose '$purpose' at index $statusListIndex: $statusValue")
        return mapOf(purpose to CredentialStatusResult(statusValue == validStatusValue, null))
    }

    private fun isValid(statusSize: Int): Boolean = statusSize > 0

    private fun validateCredentialStatusEntry(entry: Map<*, *>) {
        val entryType = entry[TYPE]?.toString()
            ?: throw StatusCheckException(
                "Missing '$TYPE' in credentialStatus entry",
                STATUS_VERIFICATION_ERROR
            )

        if (entryType != BITSTRING_STATUS_LIST_ENTRY) {
            throw StatusCheckException(
                "Invalid credentialStatus.type: Expected '$BITSTRING_STATUS_LIST_ENTRY', found '$entryType'",
                STATUS_VERIFICATION_ERROR
            )
        }

        val statusListCredentialUrl = entry[STATUS_LIST_CREDENTIAL]?.toString()
            ?: throw StatusCheckException(
                "Missing '$STATUS_LIST_CREDENTIAL'",
                STATUS_RETRIEVAL_ERROR
            )

        entry[STATUS_LIST_INDEX]?.toString()?.toIntOrNull()
            ?: throw StatusCheckException(
                "Invalid or missing '$STATUS_LIST_INDEX'",
                INVALID_INDEX
            )

        if (!isValidUri(statusListCredentialUrl)) {
            throw StatusCheckException(
                "$STATUS_LIST_CREDENTIAL must be a valid URL",
                STATUS_VERIFICATION_ERROR
            )
        }
    }

    private fun decodeEncodedList(encodedList: String): ByteArray {
        val actualEncoded = if (encodedList.startsWith("u")) encodedList else "u$encodedList"
        val base64urlPart = actualEncoded.substring(1)
        val compressedBytes = try {
            Base64Decoder().decodeFromBase64Url(base64urlPart)
        } catch (ex: IllegalArgumentException) {
            logger.severe("Base64url decoding failed: ${ex.message}")
            throw StatusCheckException(
                "Base64url decoding failed",
                BASE64_DECODE_FAILED
            )
        }
        return decompressGzip(compressedBytes)
    }

    private fun decompressGzip(compressed: ByteArray): ByteArray {
        try {
            ByteArrayInputStream(compressed).use { bais ->
                GZIPInputStream(bais).use { gzipIS ->
                    val baos = ByteArrayOutputStream()
                    val buffer = ByteArray(8192)
                    var bytesRead: Int
                    while (gzipIS.read(buffer).also { bytesRead = it } != -1) {
                        baos.write(buffer, 0, bytesRead)
                    }
                    return baos.toByteArray()
                }
            }
        } catch (ex: IOException) {
            logger.severe("GZIP decompression failed: ${ex.message}")
            throw StatusCheckException(
                "Failed to decompress GZIP",
                GZIP_DECOMPRESS_FAILED
            )
        }
    }

    /**
     * Reads multiple bits starting at [position], spanning [statusSize] bits,
     * and returns the combined integer value.
     */
    private fun readBits(position: Int, bitSet: ByteArray, statusSize: Int): Int {
        var value = 0
        for (i in 0 until statusSize) {
            if (readBit(position + i, bitSet)) {
                value = value or (1 shl (statusSize - i - 1))
            }
        }
        return value
    }

    /**
     * Reads a single bit from the bitset.
     */
    private fun readBit(position: Int, bitSet: ByteArray): Boolean {
        val setBit = 1
        val bitsPerByte = 8
        val byteIndex = position / bitsPerByte
        val bitIndex = position % bitsPerByte
        if (byteIndex >= bitSet.size) {
            throw StatusCheckException(
                "Position $position exceeds bitset length",
                RANGE_ERROR
            )
        }
        val targetByte = bitSet[byteIndex].toInt()
        return ((targetByte shr (7 - bitIndex)) and 1) == setBit
    }

    private fun isStatusMessageAvailable(statusSize: Int): Boolean = statusSize > 1
}

