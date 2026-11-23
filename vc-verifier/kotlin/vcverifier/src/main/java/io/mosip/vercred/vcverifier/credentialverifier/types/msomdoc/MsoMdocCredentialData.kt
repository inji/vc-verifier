package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DIGEST_ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALUE_DIGESTS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUER_SIGNED_ITEM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUER_SIGNED_ITEM_CONTENT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALUE_DIGESTS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_DIGEST_ID
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils.getOrNull
import io.mosip.vercred.vcverifier.utils.Util
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.util.logging.Logger


typealias IssuerAuth = Array?
typealias IssuerSignedNamespaces = Map

private val logger = Logger.getLogger(MsoMdocCredentialData::class.java.name)

/**
 * One received IssuerSignedItem, decoded by [decodeIssuerSignedItems].
 *
 * @param index position in its namespace array; it lines up with the as-received bytes used for
 *   the digest.
 * @param encoded the tag-24 byte string as parsed (IssuerSignedItemBytes).
 * @param random the salt, or null when absent. Its length is checked by the verifier.
 */
internal data class DecodedIssuerSignedItem(
    val namespace: String,
    val digestId: BigInteger,
    val elementIdentifier: String,
    val elementValue: DataItem,
    val index: Int = 0,
    val random: DataItem? = null,
    val encoded: ByteString? = null,
)

/**
 * Decodes every IssuerSignedItem in [namespaces]. Used by both validation (docType field checks,
 * before the signature) and verification (digests), so items are read the same way in both.
 *
 * Each item must be a tag-24 byte string holding a map with a text `elementIdentifier`, an
 * `elementValue` and an unsigned `digestID`. Range, salt and duplicate checks are left to the
 * verifier.
 */
internal fun decodeIssuerSignedItems(namespaces: IssuerSignedNamespaces): List<DecodedIssuerSignedItem> =
    namespaces.keys.flatMap { namespaceKey ->
        val namespace = (namespaceKey as? UnicodeString)?.string
            ?: throw ValidationException(
                ERROR_MESSAGE_INVALID_VALUE_DIGESTS,
                ERROR_CODE_INVALID_VALUE_DIGESTS
            )
        val namespaceData = (namespaces[namespaceKey] as? Array)?.dataItems
            ?: throw ValidationException(
                ERROR_MESSAGE_INVALID_ISSUER_SIGNED_ITEM,
                ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
            )
        namespaceData.mapIndexed { index, item -> decodeIssuerSignedItem(namespace, index, item) }
    }

private fun decodeIssuerSignedItem(namespace: String, index: Int, item: DataItem): DecodedIssuerSignedItem {
    if (item !is ByteString || item.tag?.value != TAG_ENCODED_CBOR) {
        throw ValidationException(
            ERROR_MESSAGE_INVALID_ISSUER_SIGNED_ITEM,
            ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
        )
    }
    val decodedMap = try {
        CborDecoder(ByteArrayInputStream(item.bytes)).decode().firstOrNull() as? Map
    } catch (exception: Exception) {
        logger.severe("Unable to decode item $index in namespace '$namespace': ${exception.message}")
        null
    } ?: throw ValidationException(
        ERROR_MESSAGE_INVALID_ISSUER_SIGNED_ITEM_CONTENT,
        ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
    )
    val elementIdentifier = (decodedMap.getOrNull(ELEMENT_IDENTIFIER) as? UnicodeString)?.string
    val elementValue = decodedMap.getOrNull(ELEMENT_VALUE)
    if (elementIdentifier == null || elementValue == null) {
        throw ValidationException(
            ERROR_MESSAGE_INVALID_ISSUER_SIGNED_ITEM_CONTENT,
            ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
        )
    }
    val digestId = (decodedMap.getOrNull(DIGEST_ID) as? UnsignedInteger)?.value
        ?: throw ValidationException(ERROR_MESSAGE_MISSING_DIGEST_ID, ERROR_CODE_INVALID_DIGEST_ID)
    return DecodedIssuerSignedItem(
        namespace = namespace,
        digestId = digestId,
        elementIdentifier = elementIdentifier,
        elementValue = elementValue,
        index = index,
        random = decodedMap.getOrNull(RANDOM),
        encoded = item,
    )
}

/**
 * Value of [identifier] in [namespace] as text (a tstr's content, otherwise its toString()),
 * or null when the element is not disclosed.
 */
internal fun List<DecodedIssuerSignedItem>.elementText(identifier: String, namespace: String): String? {
    val value = firstOrNull { it.namespace == namespace && it.elementIdentifier == identifier }
        ?.elementValue
        ?: return null
    return (value as? UnicodeString)?.string ?: value.toString()
}

fun IssuerAuth.extractMso(): Map {
    if (this == null) {
        logger.severe("IssuerAuth in credential is not available")
        throw RuntimeException("Invalid Issuer Auth")
    }

    // Only the ISO form is accepted: #6.24(bstr .cbor MobileSecurityObject).
    val payload = CborDecoder.decode((this[2] as ByteString).bytes)[0]
    if (payload !is ByteString || payload.tag?.value != TAG_ENCODED_CBOR) {
        throw RuntimeException("Invalid Issuer Auth")
    }
    return CborDecoder.decode(payload.bytes)[0] as? Map
        ?: throw RuntimeException("Invalid Issuer Auth")
}

/**
 * Document signer certificate from the unprotected x5chain header.
 * A certificate present only in the protected header is ignored.
 */
internal fun extractDocumentSignerCertificate(issuerAuth: Array): X509Certificate? {
    return try {
        val unprotectedHeader = issuerAuth[1] as? Map ?: return null
        val x5Chain: DataItem = unprotectedHeader.get(UnsignedInteger(X5C)) ?: return null
        val issuerCertificateString: DataItem? = when (x5Chain.majorType) {
            MajorType.BYTE_STRING -> x5Chain
            MajorType.ARRAY -> (x5Chain as Array)[0]
            else -> null
        }
        if (issuerCertificateString !is ByteString) {
            return null
        }
        Util.toX509Certificate(issuerCertificateString.bytes)
    } catch (_: Exception) {
        null
    }
}

data class MsoMdocCredentialData(
    val docType: DataItem?,
    val issuerSigned: IssuerSigned,
    val mso: Map,
    val issuerCertificate: X509Certificate? = null,
) {
    /**
     * @param encodedNameSpaceItems exact on-the-wire CBOR bytes for each nameSpaces array
     * element (full tag-24 IssuerSignedItemBytes), keyed by namespace string and aligned
     * with the decoded [namespaces] array order.
     */
    data class IssuerSigned(
        val issuerAuth: IssuerAuth,
        val namespaces: IssuerSignedNamespaces,
        val encodedNameSpaceItems: kotlin.collections.Map<String, List<ByteArray>>,
    )
}
