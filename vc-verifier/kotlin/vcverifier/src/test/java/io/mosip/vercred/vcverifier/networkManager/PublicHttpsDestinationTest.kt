package io.mosip.vercred.vcverifier.networkManager

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress

class PublicHttpsDestinationTest {

    @Test
    fun `https public host is allowed`() {
        assertTrue(PublicHttpsDestination.isAllowedUri("https://example.com/statuslists/1"))
    }

    @Test
    fun `http is rejected`() {
        assertFalse(PublicHttpsDestination.isAllowedUri("http://example.com/statuslists/1"))
    }

    @Test
    fun `userinfo is rejected`() {
        assertFalse(PublicHttpsDestination.isAllowedUri("https://user@example.com/statuslists/1"))
    }

    @Test
    fun `loopback and localhost are rejected`() {
        assertFalse(PublicHttpsDestination.isAllowedUri("https://127.0.0.1/status"))
        assertFalse(PublicHttpsDestination.isAllowedUri("https://localhost/status"))
        assertFalse(PublicHttpsDestination.isAllowedUri("https://[::1]/status"))
    }

    @Test
    fun `private and link-local literals are rejected`() {
        assertFalse(PublicHttpsDestination.isAllowedUri("https://10.0.0.1/status"))
        assertFalse(PublicHttpsDestination.isAllowedUri("https://192.168.1.1/status"))
        assertFalse(PublicHttpsDestination.isAllowedUri("https://172.16.0.1/status"))
        assertFalse(PublicHttpsDestination.isAllowedUri("https://169.254.169.254/status"))
    }

    @Test
    fun `loopback InetAddress is blocked`() {
        assertTrue(PublicHttpsDestination.isBlockedAddress(InetAddress.getByName("127.0.0.1")))
        assertTrue(PublicHttpsDestination.isBlockedHostname("localhost"))
    }
}
