package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc

import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.mdl.MDL_DOCTYPE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.mdl.MDL_NAMESPACE
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
import io.mosip.vercred.vcverifier.exception.ValidationException
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import testutils.MdlEdgeCaseTestDataGenerator
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.util.Base64

class MsoMdocNameSpacesRawBytesTest {

    private fun encode(item: DataItem): ByteArray =
        ByteArrayOutputStream().also { CborEncoder(it).encode(item) }.toByteArray()

    private fun taggedItem(identifier: String): ByteString {
        val inner = Map().apply {
            put(UnicodeString("digestID"), UnsignedInteger(0))
            put(UnicodeString("elementIdentifier"), UnicodeString(identifier))
        }
        return ByteString(encode(inner)).apply { setTag(24) }
    }

    private fun nameSpaces(vararg identifiers: String) = Map().apply {
        put(UnicodeString(MDL_NAMESPACE), Array().apply { identifiers.forEach { add(taggedItem(it)) } })
    }

    private fun issuerSigned(namespaces: Map) = Map().apply {
        put(UnicodeString("issuerAuth"), Array())
        put(UnicodeString("nameSpaces"), namespaces)
    }

    private fun identifiersOf(raw: kotlin.collections.Map<String, List<ByteArray>>): List<String> =
        raw.getValue(MDL_NAMESPACE).map { bytes ->
            val tagged = CborDecoder(ByteArrayInputStream(bytes)).decode()[0] as ByteString
            val inner = CborDecoder(ByteArrayInputStream(tagged.bytes)).decode()[0] as Map
            (inner[UnicodeString("elementIdentifier")] as UnicodeString).string
        }

    @Test
    fun `should capture items for shape A`() {
        val credential = issuerSigned(nameSpaces("a", "b"))
        val raw = MsoMdocNameSpacesRawBytes.extract(encode(credential))
        assertEquals(listOf("a", "b"), identifiersOf(raw))
        assertArrayEquals(encode(taggedItem("a")), raw.getValue(MDL_NAMESPACE)[0])
    }

    @Test
    fun `should capture items for shape B`() {
        val credential = Map().apply {
            put(UnicodeString("docType"), UnicodeString(MDL_DOCTYPE))
            put(UnicodeString("issuerSigned"), issuerSigned(nameSpaces("a")))
        }
        assertEquals(listOf("a"), identifiersOf(MsoMdocNameSpacesRawBytes.extract(encode(credential))))
    }

    @Test
    fun `should capture documents 0 for shape C with two documents`() {
        fun document(vararg ids: String) = Map().apply {
            put(UnicodeString("docType"), UnicodeString(MDL_DOCTYPE))
            put(UnicodeString("issuerSigned"), issuerSigned(nameSpaces(*ids)))
        }
        val credential = Map().apply {
            put(UnicodeString("documents"), Array().apply {
                add(document("first"))
                add(document("second", "third"))
            })
        }
        assertEquals(listOf("first"), identifiersOf(MsoMdocNameSpacesRawBytes.extract(encode(credential))))
    }

    @Test
    fun `should prefer shape C when input mixes documents and top-level nameSpaces`() {
        // Matches getIssuerSignedData, which checks documents first.
        val credential = Map().apply {
            put(UnicodeString("nameSpaces"), nameSpaces("latest"))
            put(UnicodeString("issuerAuth"), Array())
            put(UnicodeString("documents"), Array().apply {
                add(Map().apply { put(UnicodeString("issuerSigned"), issuerSigned(nameSpaces("documents"))) })
            })
        }
        assertEquals(listOf("documents"), identifiersOf(MsoMdocNameSpacesRawBytes.extract(encode(credential))))
    }

    @Test
    fun `should reject indefinite-length arrays`() {
        // { "nameSpaces": { ns: [_ item ] } }
        val item = encode(taggedItem("a"))
        val bytes = byteArrayOf(0xa1.toByte()) + encode(UnicodeString("nameSpaces")) +
            byteArrayOf(0xa1.toByte()) + encode(UnicodeString(MDL_NAMESPACE)) +
            byteArrayOf(0x9f.toByte()) + item + byteArrayOf(0xff.toByte())
        assertThrows(IllegalArgumentException::class.java) { MsoMdocNameSpacesRawBytes.extract(bytes) }
    }

    @Test
    fun `should map scanner failure to ERR_INVALID_ISSUER_SIGNED_ITEM in parse`() {
        // A real signed credential whose nameSpaces array is re-written with indefinite length:
        // cbor-java accepts it, the raw-bytes scanner deliberately does not.
        val definite = Base64.getUrlDecoder().decode(MdlEdgeCaseTestDataGenerator.create(discloseOnly = setOf("family_name")))
        val namespaceKey = encode(UnicodeString(MDL_NAMESPACE))
        // Last occurrence: the same text also appears as a valueDigests key inside the MSO.
        val keyIndex = lastIndexOf(definite, namespaceKey)
        val arrayHeaderIndex = keyIndex + namespaceKey.size
        assertEquals(0x81.toByte(), definite[arrayHeaderIndex])
        val indefinite = definite.copyOfRange(0, arrayHeaderIndex) +
            byteArrayOf(0x9f.toByte()) +
            definite.copyOfRange(arrayHeaderIndex + 1, definite.size) +
            byteArrayOf(0xff.toByte())

        val exception = assertThrows(ValidationException::class.java) {
            MsoMdocVerifiableCredential().parse(Base64.getUrlEncoder().withoutPadding().encodeToString(indefinite))
        }
        assertEquals(ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM, exception.errorCode)
    }

    @Test
    fun `should reject every truncation cleanly`() {
        val bytes = encode(issuerSigned(nameSpaces("a", "b")))
        for (length in 0 until bytes.size) {
            val exception = runCatching { MsoMdocNameSpacesRawBytes.extract(bytes.copyOf(length)) }.exceptionOrNull()
            assertTrue(
                exception is EOFException || exception is IllegalArgumentException,
                "truncated at $length: ${exception?.javaClass}"
            )
        }
    }

    @Test
    fun `should not pre-allocate from an untrusted array length`() {
        // { "nameSpaces": { ns: array(2^31-1) } } with no items.
        val bytes = byteArrayOf(0xa1.toByte()) + encode(UnicodeString("nameSpaces")) +
            byteArrayOf(0xa1.toByte()) + encode(UnicodeString(MDL_NAMESPACE)) +
            byteArrayOf(0x9a.toByte(), 0x7f, 0xff.toByte(), 0xff.toByte(), 0xff.toByte())
        assertThrows(EOFException::class.java) { MsoMdocNameSpacesRawBytes.extract(bytes) }
    }

    @Test
    fun `should skip non-text keys the same way cbor-java lookups ignore them`() {
        val credential = issuerSigned(nameSpaces("a")).apply {
            put(UnsignedInteger(7), UnicodeString("ignored"))
            (get(UnicodeString("nameSpaces")) as Map).put(UnsignedInteger(1), Array().apply { add(taggedItem("x")) })
        }
        val raw = MsoMdocNameSpacesRawBytes.extract(encode(credential))
        assertEquals(setOf(MDL_NAMESPACE), raw.keys)
        assertEquals(listOf("a"), identifiersOf(raw))
    }

    @Test
    fun `should resolve duplicate namespace keys like cbor-java`() {
        // { "nameSpaces": { ns: [a], ns: [b, c] } } built by hand (cbor-java cannot encode duplicates).
        val namespaceKey = encode(UnicodeString(MDL_NAMESPACE))
        val bytes = byteArrayOf(0xa1.toByte()) + encode(UnicodeString("nameSpaces")) +
            byteArrayOf(0xa2.toByte()) +
            namespaceKey + byteArrayOf(0x81.toByte()) + encode(taggedItem("a")) +
            namespaceKey + byteArrayOf(0x82.toByte()) + encode(taggedItem("b")) + encode(taggedItem("c"))

        val decoded = CborDecoder(ByteArrayInputStream(bytes)).decode()[0] as Map
        val decodedItems = ((decoded[UnicodeString("nameSpaces")] as Map)[UnicodeString(MDL_NAMESPACE)] as Array).dataItems
        val raw = MsoMdocNameSpacesRawBytes.extract(bytes)

        assertEquals(decodedItems.size, raw.getValue(MDL_NAMESPACE).size)
        assertEquals(listOf("b", "c"), identifiersOf(raw))
    }

    private fun lastIndexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in haystack.size - needle.size downTo 0) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        error("not found")
    }
}
