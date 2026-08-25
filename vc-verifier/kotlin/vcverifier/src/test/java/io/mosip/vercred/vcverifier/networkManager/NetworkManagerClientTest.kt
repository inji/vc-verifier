package io.mosip.vercred.vcverifier.networkManager

import io.mosip.vercred.vcverifier.exception.NetworkManagerClientExceptions
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class NetworkManagerClientTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer().apply { start() }
    }

    @AfterEach
    fun tearDown() {
        NetworkPolicy.restrictToPublicHosts = true
        NetworkPolicy.followRedirects = false
        server.shutdown()
    }

    private fun url() = server.url("/resource").toString()

    @Test
    fun `refuses a host resolving to a non-public address`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"ok":true}"""))

        val error = assertThrows(NetworkManagerClientExceptions.NetworkRequestFailed::class.java) {
            NetworkManagerClient.sendHTTPRequest(url(), HttpMethod.GET)
        }

        assertTrue(error.message!!.contains("Refusing non-public host"))
    }

    @Test
    fun `allows a non-public host when the deployment opts out`() {
        NetworkPolicy.restrictToPublicHosts = false
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"ok":true}"""))

        val response = NetworkManagerClient.sendHTTPRequest(url(), HttpMethod.GET)

        assertEquals(true, response!!["ok"])
    }

    @Test
    fun `refuses a response larger than the size limit`() {
        NetworkPolicy.restrictToPublicHosts = false
        val oversized = """{"padding":"${"a".repeat(4096)}"}"""
        server.enqueue(MockResponse().setResponseCode(200).setBody(oversized))

        val error = assertThrows(NetworkManagerClientExceptions.NetworkRequestFailed::class.java) {
            NetworkManagerClient.sendHTTPRequest(url(), HttpMethod.GET, maxResponseBytes = 1024)
        }

        assertTrue(error.message!!.contains("exceeds the 1024 byte limit"))
    }

    @Test
    fun `refuses a redirect by default and names the target`() {
        NetworkPolicy.restrictToPublicHosts = false
        server.enqueue(
            MockResponse().setResponseCode(302)
                .setHeader("Location", server.url("/moved").toString())
        )

        val error = assertThrows(NetworkManagerClientExceptions.NetworkRequestFailed::class.java) {
            NetworkManagerClient.sendHTTPRequest(url(), HttpMethod.GET)
        }

        assertTrue(error.message!!.contains("Refusing to follow redirect"))
        assertTrue(error.message!!.contains("/moved"))
    }

    @Test
    fun `follows a redirect when the deployment opts in`() {
        NetworkPolicy.restrictToPublicHosts = false
        NetworkPolicy.followRedirects = true
        server.enqueue(
            MockResponse().setResponseCode(302)
                .setHeader("Location", server.url("/moved").toString())
        )
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"ok":true}"""))

        val response = NetworkManagerClient.sendHTTPRequest(url(), HttpMethod.GET)

        assertEquals(true, response!!["ok"])
    }

    @Test
    fun `never follows a redirect that downgrades to plaintext, even when opted in`() {
        NetworkPolicy.restrictToPublicHosts = false
        NetworkPolicy.followRedirects = true
        server.enqueue(
            MockResponse().setResponseCode(302)
                .setHeader("Location", "http://insecure.example/resource")
        )

        assertThrows(NetworkManagerClientExceptions.NetworkRequestFailed::class.java) {
            NetworkManagerClient.sendHTTPRequest(url(), HttpMethod.GET)
        }
    }
}
