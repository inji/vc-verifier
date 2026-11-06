package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_DECOMPRESSION_FAILED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_INDEX_OUT_OF_BOUNDS
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_MALFORMED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PROFILE_UNSUPPORTED
import io.mosip.vercred.vcverifier.data.MdocCredentialStatus
import io.mosip.vercred.vcverifier.testHelpers.MdocStatusListFixtures
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class MdocStatusBitReaderTest {

    private val reader = MdocStatusBitReader()

    @Test
    fun `bits 1 value 0 is VALID`() {
        assertEquals(MdocCredentialStatus.VALID, read(1, intArrayOf(0)))
    }

    @Test
    fun `bits 1 value 1 is INVALID`() {
        assertEquals(MdocCredentialStatus.INVALID, read(1, intArrayOf(1)))
    }

    @Test
    fun `bits 2 value 0 is VALID`() {
        assertEquals(MdocCredentialStatus.VALID, read(2, intArrayOf(0)))
    }

    @Test
    fun `bits 2 value 1 is INVALID`() {
        assertEquals(MdocCredentialStatus.INVALID, read(2, intArrayOf(1)))
    }

    @Test
    fun `bits 2 value 2 is SUSPENDED`() {
        assertEquals(MdocCredentialStatus.SUSPENDED, read(2, intArrayOf(2)))
    }

    @Test
    fun `bits 2 value 3 is malformed and not VALID`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            read(2, intArrayOf(3))
        }
        assertEquals(STATUS_LIST_MALFORMED, exception.errorCode)
    }

    @Test
    fun `bits 4 is unsupported`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            read(4, intArrayOf(0))
        }
        assertEquals(STATUS_PROFILE_UNSUPPORTED, exception.errorCode)
    }

    @Test
    fun `index past inflated bits is out of bounds`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            reader.readStatus(MdocStatusListFixtures.zlibCompress(ByteArray(0)), 1, 0)
        }
        assertEquals(STATUS_LIST_INDEX_OUT_OF_BOUNDS, exception.errorCode)
    }

    @Test
    fun `garbage lst fails decompression`() {
        val exception = assertThrows(MdocStatusCheckException::class.java) {
            reader.readStatus(byteArrayOf(0x00, 0x01, 0x02), 1, 0)
        }
        assertEquals(STATUS_LIST_DECOMPRESSION_FAILED, exception.errorCode)
    }

    private fun read(bits: Int, values: IntArray): MdocCredentialStatus {
        val compressed = MdocStatusListFixtures.zlibCompress(MdocStatusListFixtures.packBits(bits, values))
        return reader.readStatus(compressed, bits, 0)
    }
}
