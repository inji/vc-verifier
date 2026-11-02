package io.mosip.vercred.vcverifier.utils

import java.io.EOFException
import java.math.BigInteger

/**
 * Minimal definite-length CBOR walker used to capture exact on-the-wire item bytes.
 * Indefinite-length items are rejected — mdoc IssuerSignedItemBytes use definite encoding.
 */
internal class CborByteScanner(private val data: ByteArray) {
    var position: Int = 0
        private set

    fun remaining(): Int = data.size - position

    fun takeItemBytes(): ByteArray {
        val start = position
        skipItem()
        return data.copyOfRange(start, position)
    }

    fun skipItem() {
        val initial = readInitial()
        val major = initial ushr 5
        val additional = initial and 0x1f
        when (major) {
            0, 1 -> skipArgument(additional) // unsigned / negative int
            2, 3 -> { // bstr / tstr
                val length = readLength(additional)
                requireNonNegativeInt(length)
                skip(length.toInt())
            }
            4 -> { // array
                val length = readLength(additional)
                requireNonNegativeInt(length)
                repeat(length.toInt()) { skipItem() }
            }
            5 -> { // map
                val length = readLength(additional)
                requireNonNegativeInt(length)
                repeat(length.toInt()) {
                    skipItem() // key
                    skipItem() // value
                }
            }
            6 -> { // tag — argument then one content item
                skipArgument(additional)
                skipItem()
            }
            7 -> { // simple / float
                when (additional) {
                    24 -> skip(1)
                    25 -> skip(2)
                    26 -> skip(4)
                    27 -> skip(8)
                    in 0..23 -> Unit
                    else -> throw IllegalArgumentException("Unsupported CBOR simple/float additional: $additional")
                }
            }
            else -> throw IllegalArgumentException("Unsupported CBOR major type: $major")
        }
    }

    fun readTextString(): String {
        val initial = readInitial()
        val major = initial ushr 5
        require(major == 3) { "Expected text string, major=$major" }
        val length = readLength(initial and 0x1f)
        requireNonNegativeInt(length)
        val start = position
        skip(length.toInt())
        return String(data, start, length.toInt(), Charsets.UTF_8)
    }

    fun peekMajor(): Int {
        require(position < data.size) { "Unexpected end of CBOR data" }
        return (data[position].toInt() and 0xff) ushr 5
    }

    fun readMapSize(): Int {
        val initial = readInitial()
        require(initial ushr 5 == 5) { "Expected map" }
        val length = readLength(initial and 0x1f)
        requireNonNegativeInt(length)
        return length.toInt()
    }

    fun readArraySize(): Int {
        val initial = readInitial()
        require(initial ushr 5 == 4) { "Expected array" }
        val length = readLength(initial and 0x1f)
        requireNonNegativeInt(length)
        return length.toInt()
    }

    private fun readInitial(): Int {
        if (position >= data.size) throw EOFException("Unexpected end of CBOR data")
        val value = data[position].toInt() and 0xff
        position++
        return value
    }

    private fun skipArgument(additional: Int) {
        when (additional) {
            in 0..23 -> Unit
            24 -> skip(1)
            25 -> skip(2)
            26 -> skip(4)
            27 -> skip(8)
            31 -> throw IllegalArgumentException("Indefinite-length CBOR is not supported for raw capture")
            else -> throw IllegalArgumentException("Unsupported CBOR additional info: $additional")
        }
    }

    private fun readLength(additional: Int): BigInteger {
        return when (additional) {
            in 0..23 -> BigInteger.valueOf(additional.toLong())
            24 -> BigInteger.valueOf(readFixed(1))
            25 -> BigInteger.valueOf(readFixed(2))
            26 -> BigInteger.valueOf(readFixed(4))
            27 -> BigInteger(1, readBytes(8))
            31 -> throw IllegalArgumentException("Indefinite-length CBOR is not supported for raw capture")
            else -> throw IllegalArgumentException("Unsupported CBOR additional info: $additional")
        }
    }

    private fun readFixed(size: Int): Long {
        var value = 0L
        repeat(size) {
            if (position >= data.size) throw EOFException("Unexpected end of CBOR data")
            value = (value shl 8) or (data[position].toInt() and 0xff).toLong()
            position++
        }
        return value
    }

    private fun readBytes(size: Int): ByteArray {
        if (position + size > data.size) throw EOFException("Unexpected end of CBOR data")
        val out = data.copyOfRange(position, position + size)
        position += size
        return out
    }

    private fun skip(size: Int) {
        if (position + size > data.size) throw EOFException("Unexpected end of CBOR data")
        position += size
    }

    private fun requireNonNegativeInt(length: BigInteger) {
        if (length.signum() < 0 || length > BigInteger.valueOf(Int.MAX_VALUE.toLong())) {
            throw IllegalArgumentException("CBOR length out of range: $length")
        }
    }
}
