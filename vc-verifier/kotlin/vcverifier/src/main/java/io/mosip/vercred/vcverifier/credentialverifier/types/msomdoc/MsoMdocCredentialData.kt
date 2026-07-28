package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.*
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.Map
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MSO
import io.mosip.vercred.vcverifier.exception.ValidationException
import java.util.logging.Logger


typealias IssuerAuth = Array?
typealias IssuerSignedNamespaces = Map

private val logger = Logger.getLogger(MsoMdocCredentialData::class.java.name)


fun IssuerSignedNamespaces.extractFieldValue(fieldToBeExtracted: String): String {
    val issuerSignedNamespacedData = this
    issuerSignedNamespacedData.keys.forEach { namespace ->
        run {
            val namespaceData: List<DataItem> =
                ((issuerSignedNamespacedData[namespace]) as Array).dataItems

            namespaceData.forEach { issuerSignedItem ->
                val encodedIssuerSignedItem = ByteArrayOutputStream()
                CborEncoder(encodedIssuerSignedItem).encode(issuerSignedItem)
                val decodedIssuerSignedItem =
                    CborDecoder(ByteArrayInputStream((issuerSignedItem as ByteString).bytes)).decode()[0] as Map
                val elementIdentifier: String =
                    ((decodedIssuerSignedItem["elementIdentifier"]) as UnicodeString).string

                if (elementIdentifier == fieldToBeExtracted) {
                    return (decodedIssuerSignedItem["elementValue"] as UnicodeString).string
                }
            }
        }
    }
    return ""
}

fun IssuerAuth.extractMso(isLatest: Boolean = true): Map {
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
        if (isLatest && decodedPayload?.tag != Tag(24)) {
            throw ValidationException("mso is not tagged", ERROR_CODE_INVALID_MSO)
        }
        val decodedPayloadLevel2: DataItem? =
            CborDecoder.decode((decodedPayload as ByteString).bytes)[0]
        mso = decodedPayloadLevel2 as Map
    } else {
        throw RuntimeException("Invalid Issuer Auth")
    }
    return mso
}

data class MsoMdocCredentialData(val docType: DataItem?, val issuerSigned: IssuerSigned, val mso: Map) {
    data class IssuerSigned(val issuerAuth: IssuerAuth, val namespaces: IssuerSignedNamespaces)
}

