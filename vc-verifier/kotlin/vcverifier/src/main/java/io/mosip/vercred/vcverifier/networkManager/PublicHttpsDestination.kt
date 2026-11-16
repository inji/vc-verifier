package io.mosip.vercred.vcverifier.networkManager

import okhttp3.Dns
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.net.UnknownHostException

/**
 * SSRF guard for status-list fetches: HTTPS only, no loopback / link-local / private destinations.
 * Hostnames are checked again at OkHttp DNS/connect time because DNS can change after the URI check.
 */
internal object PublicHttpsDestination {

    private val IPV4_LITERAL = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

    fun isAllowedUri(value: String): Boolean {
        val uri = try {
            URI(value)
        } catch (_: Exception) {
            return false
        }
        if (!uri.scheme.equals("https", ignoreCase = true)) {
            return false
        }
        val host = normalizeHost(uri.host)
        if (host.isNullOrEmpty() || !uri.userInfo.isNullOrEmpty()) {
            return false
        }
        if (isBlockedHostname(host)) {
            return false
        }
        val looksLikeIp = host.contains(':') || host.matches(IPV4_LITERAL)
        if (looksLikeIp) {
            val literal = literalAddress(host) ?: return false
            return !isBlockedAddress(literal)
        }
        return true
    }

    private fun normalizeHost(host: String?): String? {
        if (host.isNullOrEmpty()) {
            return host
        }
        var normalized = host.trim().trimEnd('.').lowercase()
        if (normalized.startsWith("[") && normalized.endsWith("]")) {
            normalized = normalized.substring(1, normalized.length - 1)
        }
        return normalized
    }

    fun isBlockedHostname(hostname: String): Boolean {
        val host = hostname.trim().trimEnd('.').lowercase()
        return host == "localhost" || host.endsWith(".localhost") || isIpv6LoopbackHost(host)
    }

    private fun isIpv6LoopbackHost(host: String): Boolean {
        return host == "::1" || host == "0:0:0:0:0:0:0:1"
    }

    fun isBlockedAddress(address: InetAddress): Boolean {
        val unwrapped = unwrapMappedIpv4(address)
        return unwrapped.isAnyLocalAddress ||
            unwrapped.isLoopbackAddress ||
            unwrapped.isLinkLocalAddress ||
            unwrapped.isSiteLocalAddress ||
            unwrapped.isMulticastAddress ||
            isUniqueLocalIpv6(unwrapped)
    }

    private fun literalAddress(host: String): InetAddress? {
        val ipv4 = host.matches(IPV4_LITERAL)
        val ipv6 = host.contains(':')
        if (!ipv4 && !ipv6) {
            return null
        }
        return try {
            InetAddress.getByName(host)
        } catch (_: Exception) {
            null
        }
    }

    private fun unwrapMappedIpv4(address: InetAddress): InetAddress {
        if (address !is Inet6Address) {
            return address
        }
        val bytes = address.address
        if (bytes.size != 16) {
            return address
        }
        val mapped = (0..9).all { bytes[it] == 0.toByte() } &&
            bytes[10] == 0xFF.toByte() &&
            bytes[11] == 0xFF.toByte()
        val compatible = (0..11).all { bytes[it] == 0.toByte() }
        if (!mapped && !compatible) {
            return address
        }
        return InetAddress.getByAddress(byteArrayOf(bytes[12], bytes[13], bytes[14], bytes[15]))
    }

    private fun isUniqueLocalIpv6(address: InetAddress): Boolean {
        if (address !is Inet6Address) {
            return false
        }
        val bytes = address.address
        return bytes.isNotEmpty() && (bytes[0].toInt() and 0xFE) == 0xFC
    }
}

internal object PublicHttpsDns : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        if (PublicHttpsDestination.isBlockedHostname(hostname)) {
            throw UnknownHostException("Status list host is not allowed")
        }
        val addresses = Dns.SYSTEM.lookup(hostname)
        if (addresses.isEmpty() || addresses.any { PublicHttpsDestination.isBlockedAddress(it) }) {
            throw UnknownHostException("Status list host is not allowed")
        }
        return addresses
    }
}
