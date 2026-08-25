package io.mosip.vercred.vcverifier.networkManager

import io.mosip.vercred.vcverifier.exception.NetworkManagerClientExceptions
import io.mosip.vercred.vcverifier.utils.Util
import okhttp3.Dns
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.InterruptedIOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit

private const val DEFAULT_CALL_TIMEOUT_SECONDS = 10L
private const val CONNECT_TIMEOUT_SECONDS = 5L
private const val READ_TIMEOUT_SECONDS = 5L
private const val DEFAULT_MAX_RESPONSE_BYTES = 256L * 1024

object NetworkPolicy {
    @Volatile
    @JvmStatic
    var restrictToPublicHosts: Boolean = true

    @Volatile
    @JvmStatic
    var followRedirects: Boolean = false
}

class NetworkManagerClient {
    companion object {

        private val httpClient: OkHttpClient by lazy {
            OkHttpClient.Builder()
                .callTimeout(DEFAULT_CALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .followRedirects(false)
                .followSslRedirects(false)
                .dns(PublicAddressDns)
                .build()
        }

        fun sendHTTPRequest(
            url: String,
            method: HttpMethod,
            bodyParams: Map<String, String>? = null,
            headers: Map<String, String>? = null,
            maxResponseBytes: Long = DEFAULT_MAX_RESPONSE_BYTES,
            callTimeoutSeconds: Long = DEFAULT_CALL_TIMEOUT_SECONDS
        ): Map<String, Any>? {
            try {
                val request: Request
                when (method) {
                    HttpMethod.POST -> {
                        val requestBodyBuilder = FormBody.Builder()
                        bodyParams?.forEach { (key, value) ->
                            requestBodyBuilder.add(key, value)
                        }
                        val requestBody = requestBodyBuilder.build()
                        val requestBuilder = Request.Builder().url(url).post(requestBody)
                        headers?.forEach { (key, value) ->
                            requestBuilder.addHeader(key, value)
                        }
                        request = requestBuilder.build()
                    }

                    HttpMethod.GET -> request = Request.Builder().url(url).get().build()
                }
                clientFor(callTimeoutSeconds).newCall(request).execute().use { response ->
                    if (response.isRedirect) {
                        throw Exception(
                            "Refusing to follow redirect from $url to " +
                                    "${response.header("Location")}. Set NetworkPolicy.followRedirects " +
                                    "to true if this endpoint legitimately redirects."
                        )
                    }
                    if (!response.isSuccessful) throw Exception(response.toString())

                    return response.body?.let { body ->
                        if (body.contentLength() > maxResponseBytes) {
                            throw ResponseTooLargeException(maxResponseBytes)
                        }
                        Util.convertJsonToMap(
                            body.byteStream().use { readBounded(it, maxResponseBytes) }
                        )
                    }
                }
            } catch (exception: InterruptedIOException) {
                val specificException =
                    NetworkManagerClientExceptions.NetworkRequestTimeout()
                throw specificException
            } catch (exception: Exception) {
                val specificException =
                    NetworkManagerClientExceptions.NetworkRequestFailed(exception.message!!)
                throw specificException
            }
        }

        private fun clientFor(callTimeoutSeconds: Long): OkHttpClient {
            val overrideTimeout = callTimeoutSeconds != DEFAULT_CALL_TIMEOUT_SECONDS
            val allowRedirects = NetworkPolicy.followRedirects
            if (!overrideTimeout && !allowRedirects) return httpClient

            return httpClient.newBuilder()
                .apply { if (overrideTimeout) callTimeout(callTimeoutSeconds, TimeUnit.SECONDS) }
                .followRedirects(allowRedirects)
                .build()
        }

        private fun readBounded(stream: InputStream, maxResponseBytes: Long): String {
            val collected = ByteArrayOutputStream()
            val chunk = ByteArray(8192)
            var total = 0L
            while (true) {
                val read = stream.read(chunk)
                if (read == -1) break
                total += read
                if (total > maxResponseBytes) throw ResponseTooLargeException(maxResponseBytes)
                collected.write(chunk, 0, read)
            }
            return collected.toString(Charsets.UTF_8.name())
        }

        private class ResponseTooLargeException(maxResponseBytes: Long) :
            Exception("Response exceeds the $maxResponseBytes byte limit")

        private object PublicAddressDns : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                val addresses = Dns.SYSTEM.lookup(hostname)
                if (!NetworkPolicy.restrictToPublicHosts) return addresses
                if (addresses.isEmpty() || addresses.any { !it.isPublicAddress() }) {
                    throw UnknownHostException("Refusing non-public host: $hostname")
                }
                return addresses
            }
        }
    }
}

internal fun InetAddress.isPublicAddress(): Boolean {
    if (isAnyLocalAddress || isLoopbackAddress || isLinkLocalAddress ||
        isSiteLocalAddress || isMulticastAddress
    ) return false

    return when (this) {
        is Inet4Address -> isPublicIpv4(address)
        is Inet6Address -> isPublicIpv6(this)
        else -> false
    }
}

private fun ByteArray.octet(index: Int) = this[index].toInt() and 0xff

/** 10/8, 172.16/12, 192.168/16, 127/8 and 169.254/16 are already refused by [isPublicAddress]. */
private fun isPublicIpv4(bytes: ByteArray): Boolean {
    val a = bytes.octet(0)
    val b = bytes.octet(1)
    val c = bytes.octet(2)
    return when {
        a == 0 -> false                           // 0.0.0.0/8 "this network"
        a >= 224 -> false                         // multicast, 240/4 reserved, broadcast
        a == 100 && b in 64..127 -> false         // 100.64/10 carrier-grade NAT
        a == 192 && b == 0 && c == 0 -> false     // 192.0.0.0/24 IETF protocol assignments
        a == 192 && b == 0 && c == 2 -> false     // 192.0.2.0/24 TEST-NET-1
        a == 192 && b == 88 && c == 99 -> false   // 192.88.99.0/24 6to4 relay anycast
        a == 198 && b in 18..19 -> false          // 198.18.0.0/15 benchmarking
        a == 198 && b == 51 && c == 100 -> false  // 198.51.100.0/24 TEST-NET-2
        a == 203 && b == 0 && c == 113 -> false   // 203.0.113.0/24 TEST-NET-3
        else -> true
    }
}

private fun isPublicIpv6(address: Inet6Address): Boolean {
    val bytes = address.address
    if ((bytes.octet(0) and 0xfe) == 0xfc) return false // fc00::/7 unique local
    if (bytes.octet(0) == 0x20 && bytes.octet(1) == 0x01 &&
        bytes.octet(2) == 0x0d && bytes.octet(3) == 0xb8
    ) return false                                      // 2001:db8::/32 documentation

    // A transition address can look globally routable while naming an internal IPv4 target, so the
    // address it tunnels is judged on its own merits.
    embeddedIpv4(address)?.let { return it.isPublicAddress() }

    // ::/96 and ::ffff:0:0/96 — normally normalised to Inet4Address; refused defensively.
    if ((0 until 10).all { bytes[it].toInt() == 0 }) return false
    return true
}

/**
 * The IPv4 address tunnelled inside [address], or null if it tunnels none.
 *
 * Each mechanism packs the address differently, so each is matched on its own marker bytes:
 * 6to4 places it directly after the `2002:` prefix, Teredo places it last and bit-inverts it, and
 * ISATAP and NAT64 place it last unaltered. ISATAP is identified by its `00:00:5e:fe` interface
 * identifier rather than a prefix, so it can appear under a globally routable prefix.
 */
private fun embeddedIpv4(address: Inet6Address): InetAddress? {
    val bytes = address.address
    val embedded = when {
        is6to4(bytes) -> bytes.copyOfRange(2, 6)
        isTeredo(bytes) -> ByteArray(4) { (bytes[12 + it].toInt().inv() and 0xff).toByte() }
        isNat64(bytes) || isIsatap(bytes) -> bytes.copyOfRange(12, 16)
        else -> null
    }
    return embedded?.let(InetAddress::getByAddress)
}

/** 2002::/16 — RFC 3056. */
private fun is6to4(bytes: ByteArray) =
    bytes.octet(0) == 0x20 && bytes.octet(1) == 0x02

/** 2001:0::/32 — RFC 4380. */
private fun isTeredo(bytes: ByteArray) =
    bytes.octet(0) == 0x20 && bytes.octet(1) == 0x01 &&
            bytes.octet(2) == 0x00 && bytes.octet(3) == 0x00

/**
 * RFC 5214 — interface identifier `<u/g bits>:00:5e:fe`. Teredo is excluded first because a Teredo
 * address can coincidentally carry the same identifier bytes.
 */
private fun isIsatap(bytes: ByteArray) =
    !isTeredo(bytes) && (bytes.octet(8) and 0xfc) == 0x00 &&
            bytes.octet(9) == 0x00 && bytes.octet(10) == 0x5e && bytes.octet(11) == 0xfe

/** 64:ff9b::/96 — RFC 6052 well-known prefix. */
private fun isNat64(bytes: ByteArray) =
    bytes.octet(0) == 0x00 && bytes.octet(1) == 0x64 &&
            bytes.octet(2) == 0xff && bytes.octet(3) == 0x9b

enum class HttpMethod {
    POST, GET
}
