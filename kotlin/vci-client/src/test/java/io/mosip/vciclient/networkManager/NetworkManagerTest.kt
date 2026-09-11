package io.mosip.vciclient.networkManager

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.net.InetAddress
import okhttp3.Request
import org.junit.After
import org.junit.Before
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.NetworkRequestTimeoutException
import java.util.concurrent.TimeUnit

class NetworkManagerTest {
    private lateinit var server: MockWebServer

    private fun MockWebServer.localUrl(path: String) =
        url(path).newBuilder().host("127.0.0.1").build()

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start(InetAddress.getByName("127.0.0.1"), 0)
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `should return response for successful GET request`() {
        val expectedBody = "{\"success\":true}"
        server.enqueue(MockResponse().setResponseCode(200).setBody(expectedBody))
        val request = Request.Builder().url(server.localUrl("/test")).get().build()
        val response = NetworkManager.sendRequest(request)
        assertEquals(expectedBody, response.body)
    }

    @Test
    fun `should throw exception for invalid URL`() {
        assertFailsWith<Exception> {
            NetworkManager.sendRequest("http://invalid-url", HttpMethod.GET, headers = mapOf())
        }
    }


    @Test
    fun `should handle empty response body`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody(""))
        val request = Request.Builder().url(server.localUrl("/empty")).get().build()
        val response = NetworkManager.sendRequest(request)
        assertEquals("", response.body)
    }

    @Test
    fun `should expose parsed server error details for json error responses`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(400)
                .setBody("""{"error":"invalid_request","error_description":"missing proof"}""")
        )

        val exception = assertFailsWith<NetworkRequestFailedException> {
            NetworkManager.sendRequest(Request.Builder().url(server.localUrl("/error")).get().build())
        }

        assertEquals("invalid_request", exception.issuerErrorCode)
        assertEquals("missing proof", exception.issuerErrorDescription)
    }

    @Test
    fun `should preserve raw response body when error response is not json`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(500)
                .setBody("upstream failed")
        )

        val exception = assertFailsWith<NetworkRequestFailedException> {
            NetworkManager.sendRequest(Request.Builder().url(server.localUrl("/error")).get().build())
        }

        assertNull(exception.issuerErrorCode)
        assertEquals("upstream failed", exception.issuerErrorDescription)
    }

    @Test
    fun `should map call timeout to NetworkRequestTimeoutException`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("{}")
                .setBodyDelay(2, TimeUnit.SECONDS)
        )

        val exception = assertFailsWith<NetworkRequestTimeoutException> {
            NetworkManager.sendRequest(
                request = Request.Builder().url(server.localUrl("/timeout")).get().build(),
                timeoutMillis = 200
            )
        }

        assertTrue(exception.message.isNotBlank())
    }

    @Test
    fun `should reject plaintext http for non-loopback hosts`() {
        val request = Request.Builder().url("http://issuer.example.com/credential").build()

        val exception = assertFailsWith<NetworkRequestFailedException> {
            NetworkManager.sendRequest(request = request)
        }

        assertTrue(exception.message.contains("Plaintext HTTP endpoints are not allowed"))
    }
}
