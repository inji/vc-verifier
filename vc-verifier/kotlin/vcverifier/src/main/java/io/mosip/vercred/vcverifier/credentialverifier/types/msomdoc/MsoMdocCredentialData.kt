package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import java.io.ByteArrayInputStream
import java.util.logging.Logger


typealias IssuerAuth = Array?
typealias IssuerSignedNamespaces = Map

private val logger = Logger.getLogger(MsoMdocCredentialData::class.java.name)


fun IssuerSignedNamespaces.extractFieldValue(fieldToBeExtracted: String): String {
    return extractFieldValue(fieldToBeExtracted, namespaceFilter = null) ?: ""
}

fun IssuerSignedNamespaces.extractFieldValue(
    fieldToBeExtracted: String,
    namespaceFilter: String?,
): String? {
    val issuerSignedNamespacedData = this
    issuerSignedNamespacedData.keys.forEach { namespace ->
        if (namespaceFilter != null && (namespace as? UnicodeString)?.string != namespaceFilter) {
            return@forEach
        }
        val namespaceData: List<DataItem> =
            ((issuerSignedNamespacedData[namespace]) as Array).dataItems

        namespaceData.forEach { issuerSignedItem ->
            if (issuerSignedItem !is ByteString) {
                return@forEach
            }
            val decodedIssuerSignedItem =
                CborDecoder(ByteArrayInputStream(issuerSignedItem.bytes)).decode()[0] as Map
            val elementIdentifier: String =
                ((decodedIssuerSignedItem["elementIdentifier"]) as UnicodeString).string

            if (elementIdentifier == fieldToBeExtracted) {
                val elementValue = decodedIssuerSignedItem["elementValue"]
                return when (elementValue) {
                    is UnicodeString -> elementValue.string
                    else -> elementValue?.toString()
                }
            }
        }
    }
    return null
}

fun IssuerAuth.extractMso(): Map {
    if (this == null) {
        logger.severe("IssuerAuth in credential is not available")
        throw RuntimeException("Invalid Issuer Auth")
    }

    val decodedPayload: DataItem? =
        CborDecoder.decode((this[2] as ByteString).bytes)[0]
    val mso: Map
    if ((decodedPayload?.majorType ?: MajorType.INVALID) == MajorType.MAP) {
        mso = decodedPayload as Map
    } else if ((decodedPayload?.majorType ?: MajorType.ARRAY) == MajorType.BYTE_STRING) {
        val decodedPayloadLevel2: DataItem? =
            CborDecoder.decode((decodedPayload as ByteString).bytes)[0]
        mso = decodedPayloadLevel2 as Map
    } else {
        throw RuntimeException("Invalid Issuer Auth")
    }
    return mso
}

data class MsoMdocCredentialData(val docType: DataItem?, val issuerSigned: IssuerSigned, val mso: Map) {
    /**
     * @param encodedNameSpaceItems exact on-the-wire CBOR bytes for each nameSpaces array
     * element (full tag-24 IssuerSignedItemBytes), keyed by namespace string and aligned
     * with the decoded [namespaces] array order.
     */
    data class IssuerSigned(
        val issuerAuth: IssuerAuth,
        val namespaces: IssuerSignedNamespaces,
        val encodedNameSpaceItems: kotlin.collections.Map<String, List<ByteArray>> = emptyMap(),
    )
}

