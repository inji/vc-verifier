package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.IETF_BITS_1
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.IETF_BITS_2
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_DECOMPRESSION_FAILED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_INDEX_OUT_OF_BOUNDS
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_MALFORMED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PROFILE_UNSUPPORTED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_VALUE_INVALID
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_VALUE_SUSPENDED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_VALUE_UNUSED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_VALUE_VALID
import io.mosip.vercred.vcverifier.data.MdocCredentialStatus
import java.io.ByteArrayOutputStream
import java.util.zip.DataFormatException
import java.util.zip.Inflater

/**
 * Inflates a Token Status List `lst` (ZLIB+DEFLATE) and reads [bitSize] bits at [idx], LSB first.
 */
class MdocStatusBitReader {

    fun readStatus(compressedLst: ByteArray, bitSize: Int, idx: Long): MdocCredentialStatus {
        if (bitSize != IETF_BITS_1 && bitSize != IETF_BITS_2) {
            throw MdocStatusCheckException(
                STATUS_PROFILE_UNSUPPORTED,
                "Status list bits=$bitSize is not supported; IETF profile allows 1 or 2"
            )
        }
        if (idx < 0) {
            throw MdocStatusCheckException(
                STATUS_LIST_INDEX_OUT_OF_BOUNDS,
                "Status list index $idx is out of bounds"
            )
        }
        val inflated = inflate(compressedLst)
        val value = readBits(inflated, bitSize, idx)
        return mapValue(bitSize, value)
    }

    fun inflate(compressedLst: ByteArray): ByteArray {
        val inflater = Inflater()
        return try {
            inflater.setInput(compressedLst)
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            while (!inflater.finished()) {
                val count = inflater.inflate(buffer)
                if (count > 0) {
                    output.write(buffer, 0, count)
                }
                if (inflater.finished()) {
                    break
                }
                if (count == 0) {
                    throw MdocStatusCheckException(
                        STATUS_LIST_DECOMPRESSION_FAILED,
                        "ZLIB inflate of status list lst failed"
                    )
                }
            }
            output.toByteArray()
        } catch (exception: MdocStatusCheckException) {
            throw exception
        } catch (exception: DataFormatException) {
            throw MdocStatusCheckException(
                STATUS_LIST_DECOMPRESSION_FAILED,
                "ZLIB inflate of status list lst failed: ${exception.message}"
            )
        } catch (exception: Exception) {
            throw MdocStatusCheckException(
                STATUS_LIST_DECOMPRESSION_FAILED,
                "ZLIB inflate of status list lst failed: ${exception.message}"
            )
        } finally {
            inflater.end()
        }
    }

    fun readBits(inflated: ByteArray, bitSize: Int, idx: Long): Int {
        val bitIndex = idx * bitSize
        val lastBitIndex = bitIndex + bitSize - 1
        if (lastBitIndex < 0 || lastBitIndex / 8 >= inflated.size) {
            throw MdocStatusCheckException(
                STATUS_LIST_INDEX_OUT_OF_BOUNDS,
                "Status list index $idx is out of bounds"
            )
        }
        var value = 0
        for (i in 0 until bitSize) {
            val absoluteBit = bitIndex + i
            val byteIndex = (absoluteBit / 8).toInt()
            val bitOffset = (absoluteBit % 8).toInt()
            val bit = (inflated[byteIndex].toInt() shr bitOffset) and 1
            value = value or (bit shl i)
        }
        return value
    }

    private fun mapValue(bitSize: Int, value: Int): MdocCredentialStatus {
        if (bitSize == IETF_BITS_2 && value == STATUS_VALUE_UNUSED) {
            throw MdocStatusCheckException(
                STATUS_LIST_MALFORMED,
                "Unused status list value 3 is not a valid IETF status"
            )
        }
        return when (value) {
            STATUS_VALUE_VALID -> MdocCredentialStatus.VALID
            STATUS_VALUE_INVALID -> MdocCredentialStatus.INVALID
            STATUS_VALUE_SUSPENDED -> {
                if (bitSize == IETF_BITS_1) {
                    throw MdocStatusCheckException(
                        STATUS_LIST_MALFORMED,
                        "Status value $value is not valid for bits=1"
                    )
                }
                MdocCredentialStatus.SUSPENDED
            }
            else -> throw MdocStatusCheckException(
                STATUS_LIST_MALFORMED,
                "Unsupported status list value $value for bits=$bitSize"
            )
        }
    }
}
