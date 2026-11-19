package io.mosip.vercred.vcverifier.networkManager

import io.mosip.vercred.vcverifier.exception.NetworkManagerClientExceptions
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.Buffer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets

class NetworkManagerClientBytesTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setup() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun teardown() {
        server.shutdown()
    }

    @Test
    fun `body within maxBytes is returned`() {
        val payload = "status-list-cwt".toByteArray(StandardCharsets.UTF_8)
        server.enqueue(MockResponse().setResponseCode(200).setBody(String(payload, StandardCharsets.UTF_8)))

        val result = NetworkManagerClient.sendHTTPRequestBytes(
            server.url("/status").toString(),
            HttpMethod.GET,
            maxBytes = 1024
        )

        assertTrue(result.contentEquals(payload))
    }

    @Test
    fun `content-length larger than maxBytes is rejected`() {
        val payload = ByteArray(32) { 1 }
        server.enqueue(MockResponse().setResponseCode(200).setBody(Buffer().write(payload)))

        val exception = assertThrows(NetworkManagerClientExceptions.NetworkRequestFailed::class.java) {
            NetworkManagerClient.sendHTTPRequestBytes(
                server.url("/status").toString(),
                HttpMethod.GET,
                maxBytes = 8
            )
        }
        assertTrue(exception.message!!.contains("exceeds"))
    }

    @Test
    fun `chunked body larger than maxBytes is rejected`() {
        val payload = ByteArray(32) { 2 }
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setChunkedBody(Buffer().write(payload), 5)
        )

        val exception = assertThrows(NetworkManagerClientExceptions.NetworkRequestFailed::class.java) {
            NetworkManagerClient.sendHTTPRequestBytes(
                server.url("/status").toString(),
                HttpMethod.GET,
                maxBytes = 8
            )
        }
        assertTrue(exception.message!!.contains("exceeds"))
        assertEquals("/status", server.takeRequest().path)
    }
}
