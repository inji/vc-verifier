package io.mosip.vercred.vcverifier.networkManager

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress

class PublicAddressTest {

    private fun isPublic(literal: String) =
        InetAddress.getByName(literal).isPublicAddress()

    @Test
    fun `accepts globally routable addresses`() {
        listOf("8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
            .forEach { assertTrue(isPublic(it), "$it should be treated as public") }
    }

    @Test
    fun `refuses loopback, private and link-local IPv4`() {
        listOf("127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0")
            .forEach { assertFalse(isPublic(it), "$it should be refused") }
    }

    @Test
    fun `refuses special-use IPv4 ranges`() {
        listOf(
            "100.64.0.1",     // carrier-grade NAT
            "192.0.0.1",      // IETF protocol assignments
            "192.0.2.1",      // TEST-NET-1
            "192.88.99.1",    // 6to4 relay anycast
            "198.18.0.1",     // benchmarking
            "198.51.100.1",   // TEST-NET-2
            "203.0.113.1",    // TEST-NET-3
            "240.0.0.1",      // reserved
            "255.255.255.255" // broadcast
        ).forEach { assertFalse(isPublic(it), "$it should be refused") }
    }

    @Test
    fun `refuses IPv6 transition addresses that embed an internal IPv4 target`() {
        listOf(
            "2002:7f00:0001::",              // 6to4 wrapping 127.0.0.1
            "2002:0a00:0001::",              // 6to4 wrapping 10.0.0.1
            "2002:a9fe:a9fe::",              // 6to4 wrapping 169.254.169.254
            "64:ff9b::7f00:1",               // NAT64 wrapping 127.0.0.1
            "2001:0:53aa:64c:0:0:80ff:fffe", // Teredo wrapping 127.0.0.1
            "2606:2800:220::5efe:0a00:0001", // ISATAP with a global prefix, wrapping 10.0.0.1
            "fe80::5efe:7f00:1"              // ISATAP wrapping 127.0.0.1
        ).forEach { assertFalse(isPublic(it), "$it should be refused") }
    }

    @Test
    fun `allows a 6to4 address wrapping a public IPv4`() {
        assertTrue(isPublic("2002:0808:0808::"))
    }

    @Test
    fun `refuses unique-local and documentation IPv6`() {
        listOf("fc00::1", "fd00::1", "2001:db8::1", "::1", "::")
            .forEach { assertFalse(isPublic(it), "$it should be refused") }
    }

    @Test
    fun `refuses IPv4-mapped loopback`() {
        assertFalse(isPublic("::ffff:127.0.0.1"))
    }
}
