package io.mosip.vercred.vcverifier.keyResolver.types.did

import io.ipfs.multibase.Base58
import io.mockk.clearAllMocks
import io.mockk.unmockkAll
import io.mosip.vercred.vcverifier.constants.DidMethod
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.testHelpers.assertPublicKey
import io.mosip.vercred.vcverifier.testHelpers.validECR1DidKey
import io.mosip.vercred.vcverifier.testHelpers.validEdDidKey
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.PublicKey


class DidKeyPublicKeyResolverTest {
    @AfterEach
    fun tearDown() {
        clearAllMocks()
        unmockkAll()
    }

    private val resolver = DidKeyPublicKeyResolver()

    @Test
    fun `should resolve valid Ed25519 did key`() {
        val publicKey: PublicKey = resolver.extractPublicKey(createParsedDid(validEdDidKey))

        val expectedEncodedPublicKey =
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -104, 111, -113, -128, 30, 39, -124, -13, 109, 42, -42, -40, -42, 108, 43, 71, -113, 52, 13, 48, -52, 87, 69, -103, 118, 53, 52, 53, 86, 66, -93, 22]"
        assertPublicKey(publicKey, expectedEncodedPublicKey)
    }

    @Test
    fun `should resolve valid P256 did key`() {
        val es256DidKey = validECR1DidKey
        val publicKey: PublicKey = resolver.extractPublicKey(createParsedDid(es256DidKey))
        val expectedEncodedPublicKey =
            "[48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72, -50, 61, 3, 1, 7, 3, 66, 0, 4, -26, -11, 115, 86, 100, -126, 79, -47, -74, 93, 12, 14, 1, 120, -80, 119, -18, 91, 118, 43, 60, 57, -107, -91, 112, 98, -34, -86, 63, 34, -89, -92, 66, 113, -106, -40, -46, -78, -11, 101, 56, -111, 11, 41, 21, -44, -78, -9, 56, 112, 126, -127, -77, 115, -3, -119, 102, -115, 126, -31, 98, -25, 121, 95]"
        assertPublicKey(publicKey, expectedEncodedPublicKey)
    }

    @Test
    fun `should throw PublicKeyTypeNotSupportedException for unsupported key type`() {
        val prefix = byteArrayOf(0x12, 0x34)
        val pubKey = ByteArray(32) { 0x01 }
        val multicodec = prefix + pubKey
        val multibase = "z" + Base58.encode(multicodec).toString()
        val unsupportedKeyTypeDidKey = ("did:key:$multibase")

        val keyTypeNotSupportedException =
            assertThrows(PublicKeyTypeNotSupportedException::class.java) {
                resolver.extractPublicKey(createParsedDid(unsupportedKeyTypeDidKey))
            }
        print(keyTypeNotSupportedException.message)
        assertEquals(
            "KeyType - 18 is not supported. Supported: ed25519, ecr1",
            keyTypeNotSupportedException.message
        )
    }

    @Test
    fun `should throw UnknownException for invalid multibase encoding`() {
        val invalidBas58DidKey = "did:key:zINVALIDBASE58"

        val invalidBase58Exception = assertThrows(IllegalStateException::class.java) {
            resolver.extractPublicKey(createParsedDid(invalidBas58DidKey))
        }
        assertEquals("InvalidCharacter in base 58", invalidBase58Exception.message)
    }

    @Test
    fun `should throw exception for valid prefix but invalid key size`() {
        // Ed25519 prefix but only 10 bytes instead of 32
        val prefix = byteArrayOf(0xed.toByte(), 0x01.toByte())
        val pubKey = ByteArray(10) { 0x01 }
        val multicodec = prefix + pubKey
        val multibase = "z" + Base58.encode(multicodec).toString()
        val invalidKeySizeDidKey = "did:key:$multibase"

        val exception = assertThrows(PublicKeyTypeNotSupportedException::class.java) {
            resolver.extractPublicKey(createParsedDid(invalidKeySizeDidKey))
        }
        assertTrue(exception.message!!.contains("KeyType -"))
    }

    private fun createParsedDid(didKey: String) = ParsedDID(
        didKey,
        DidMethod.KEY,
        didKey.split("did:key:")[1],
        didKey,
    )
}