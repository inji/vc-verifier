package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.MSO_STATUS_IDX_KEY
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.MSO_STATUS_KEY
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.MSO_STATUS_LIST_KEY
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.MSO_STATUS_URI_KEY
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_REFERENCE_MALFORMED
import io.mosip.vercred.vcverifier.data.MsoStatusPointer
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils.getOrNull

/**
 * Reads `status.status_list {uri, idx}` from a verified MSO.
 * Missing `status` / `status_list` is not an error — status checking is skipped.
 */
class MsoStatusPointerParser {

    fun parse(mso: Map): MsoStatusPointerParseResult {
        val statusItem = mso.getOrNull(MSO_STATUS_KEY) ?: return MsoStatusPointerParseResult.Absent
        if (statusItem !is Map) {
            return malformed("MSO status is present but is not a map")
        }
        val statusListItem = statusItem.getOrNull(MSO_STATUS_LIST_KEY)
            ?: return MsoStatusPointerParseResult.Absent
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
        return MsoStatusPointerParseResult.Found(MsoStatusPointer(uriItem.string, idx))
    }

    private fun malformed(message: String) = MsoStatusPointerParseResult.Malformed(
        STATUS_REFERENCE_MALFORMED,
        message
    )
}

sealed class MsoStatusPointerParseResult {
    object Absent : MsoStatusPointerParseResult()
    data class Found(val pointer: MsoStatusPointer) : MsoStatusPointerParseResult()
    data class Malformed(val errorCode: String, val errorMessage: String) : MsoStatusPointerParseResult()
}
