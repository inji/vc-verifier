package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import io.mosip.vercred.vcverifier.utils.CborByteScanner

/**
 * Extracts the exact on-the-wire CBOR bytes of each `nameSpaces` array element
 * (`IssuerSignedItemBytes`, including the tag-24 wrapper) from a decoded mdoc credential.
 *
 * Detection order matches [MsoMdocVerifiableCredential.getIssuerSignedData]: C → B → A.
 */
internal object MsoMdocNameSpacesRawBytes {

    fun extract(credentialCbor: ByteArray): Map<String, List<ByteArray>> {
        val scanner = CborByteScanner(credentialCbor)
        val mapSize = scanner.readMapSize()
        var documentsRaw: Map<String, List<ByteArray>>? = null
        var issuerSignedRaw: Map<String, List<ByteArray>>? = null
        var latestRaw: Map<String, List<ByteArray>>? = null

        repeat(mapSize) {
            val keyMajor = scanner.peekMajor()
            if (keyMajor != 3) {
                scanner.skipItem() // key
                scanner.skipItem() // value
                return@repeat
            }
            val key = scanner.readTextString()
            when (key) {
                DOCUMENTS -> {
                    documentsRaw = readDocumentsNameSpaces(scanner)
                }
                ISSUER_SIGNED -> {
                    issuerSignedRaw = readIssuerSignedNameSpaces(scanner)
                }
                NAME_SPACES -> {
                    latestRaw = readNameSpacesMap(scanner)
                }
                else -> scanner.skipItem()
            }
        }

        return documentsRaw ?: issuerSignedRaw ?: latestRaw ?: emptyMap()
    }

    private fun readDocumentsNameSpaces(scanner: CborByteScanner): Map<String, List<ByteArray>> {
        val arraySize = scanner.readArraySize()
        if (arraySize == 0) {
            return emptyMap()
        }
        // Shape C: only documents[0] is used by parse(); capture that document's nameSpaces.
        val first = readIssuerSignedFromDocumentMap(scanner)
        repeat(arraySize - 1) { scanner.skipItem() }
        return first
    }

    private fun readIssuerSignedFromDocumentMap(scanner: CborByteScanner): Map<String, List<ByteArray>> {
        val mapSize = scanner.readMapSize()
        var result: Map<String, List<ByteArray>> = emptyMap()
        repeat(mapSize) {
            val keyMajor = scanner.peekMajor()
            if (keyMajor != 3) {
                scanner.skipItem()
                scanner.skipItem()
                return@repeat
            }
            val key = scanner.readTextString()
            if (key == ISSUER_SIGNED) {
                result = readIssuerSignedNameSpaces(scanner)
            } else {
                scanner.skipItem()
            }
        }
        return result
    }

    private fun readIssuerSignedNameSpaces(scanner: CborByteScanner): Map<String, List<ByteArray>> {
        val mapSize = scanner.readMapSize()
        var result: Map<String, List<ByteArray>> = emptyMap()
        repeat(mapSize) {
            val keyMajor = scanner.peekMajor()
            if (keyMajor != 3) {
                scanner.skipItem()
                scanner.skipItem()
                return@repeat
            }
            val key = scanner.readTextString()
            if (key == NAME_SPACES) {
                result = readNameSpacesMap(scanner)
            } else {
                scanner.skipItem()
            }
        }
        return result
    }

    private fun readNameSpacesMap(scanner: CborByteScanner): Map<String, List<ByteArray>> {
        val mapSize = scanner.readMapSize()
        val result = linkedMapOf<String, List<ByteArray>>()
        repeat(mapSize) {
            val keyMajor = scanner.peekMajor()
            if (keyMajor != 3) {
                scanner.skipItem()
                scanner.skipItem()
                return@repeat
            }
            val namespace = scanner.readTextString()
            val arraySize = scanner.readArraySize()
            val items = ArrayList<ByteArray>(arraySize)
            repeat(arraySize) {
                items.add(scanner.takeItemBytes())
            }
            result[namespace] = items
        }
        return result
    }

    private const val ISSUER_SIGNED = "issuerSigned"
}
