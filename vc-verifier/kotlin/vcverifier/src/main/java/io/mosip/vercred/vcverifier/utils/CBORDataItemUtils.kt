package io.mosip.vercred.vcverifier.utils

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.CborException
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

internal object CborDataItemUtils {
    @Throws(CborException::class)
    fun toByteArray(dataItem: DataItem?): ByteArray {
        val byteArrayOutputStream = ByteArrayOutputStream()
        val encoder = CborEncoder(byteArrayOutputStream)
        encoder.encode(dataItem)
        return byteArrayOutputStream.toByteArray()
    }

    @Throws(CborException::class)
    fun fromByteArray(byteArray: ByteArray?): DataItem {
        val dataItems: List<DataItem> = CborDecoder(ByteArrayInputStream(byteArray)).decode()

        if (dataItems.isNotEmpty()) {
            return dataItems[0]
        } else {
            throw CborException("No DataItem found in the provided byte array.")
        }
    }

    operator fun DataItem.get(name: String): DataItem {
        check(this.majorType == MajorType.MAP)
        this as Map
        return this.get(UnicodeString(name))
    }

    fun DataItem.getOrNull(name: String): DataItem? {
        if (this.majorType != MajorType.MAP) {
            return null
        }
        this as Map
        val key = UnicodeString(name)
        return if (this.keys.contains(key)) this.get(key) else null
    }

    operator fun DataItem.get(name: Long): DataItem {
        check(this.majorType == MajorType.MAP)
        this as Map
        return this.get(UnsignedInteger(name))
    }

    operator fun DataItem.get(index: Int): DataItem {
        check(this.majorType == MajorType.ARRAY)
        this as Array
        return this.dataItems[index]
    }
}
