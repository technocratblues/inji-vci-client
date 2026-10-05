package io.mosip.vciclient.authorizationServer

import io.mockk.CapturingSlot
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.slot
import io.mockk.unmockkAll
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.PushedAuthorizationRequestException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import io.mosip.vciclient.networkManager.NetworkResponse
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class PushedAuthorizationRequestServiceTest {

    private val parEndpoint = "https://as.example.com/as/par"
    private val responseBody = """{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}"""

    @Before
    fun setUp() {
        mockkObject(NetworkManager)
        mockkObject(JsonUtils)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun stubSuccessNetwork(bodySlot: CapturingSlot<Map<String, String>>) {
        every {
            NetworkManager.sendRequest(parEndpoint, HttpMethod.POST, any(), capture(bodySlot), any())
        } returns NetworkResponse(responseBody, null)
    }

    private fun stubDeserialize(response: PushedAuthorizationResponse?) {
        every {
            JsonUtils.deserialize(any(), PushedAuthorizationResponse::class.java)
        } returns response
    }

    private fun createRequest(
        clientId: String = "client-id",
        redirectUri: String = "app://callback",
        codeChallenge: String = "challenge",
        state: String = "state-123",
        nonce: String = "nonce-123",
        scope: String? = "openid",
        dpopJkt: String? = null,
        clientAuthParams: Map<String, String> = emptyMap(),
    ) = PushedAuthorizationRequest(
        parEndpoint = parEndpoint,
        client = PushedAuthorizationClientDetails(
            clientId = clientId,
            redirectUri = redirectUri,
            scope = scope,
        ),
        security = PushedAuthorizationSecurityDetails(
            codeChallenge = codeChallenge,
            state = state,
            nonce = nonce,
            dpopJkt = dpopJkt,
        ),
        options = PushedAuthorizationRequestOptions(
            clientAuthParams = clientAuthParams,
        ),
    )

    @Test
    fun `should return request_uri and expires_in on success`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:ietf:params:oauth:request_uri:abc", 90))

        val result = PushedAuthorizationRequestService().pushAuthorizationRequest(
            createRequest()
        )

        assertEquals("urn:ietf:params:oauth:request_uri:abc", result.requestUri)
        assertEquals(90L, result.expiresIn)
    }

    @Test
    fun `should always include core params including nonce`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:request_uri:abc"))

        PushedAuthorizationRequestService().pushAuthorizationRequest(
            createRequest()
        )

        val body = bodySlot.captured
        assertEquals("code", body["response_type"])
        assertEquals("client-id", body["client_id"])
        assertEquals("app://callback", body["redirect_uri"])
        assertEquals("challenge", body["code_challenge"])
        assertEquals("S256", body["code_challenge_method"])
        assertEquals("state-123", body["state"])
        assertEquals("nonce-123", body["nonce"])
    }

    @Test
    fun `should send scope and never authorization_details`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:request_uri:abc"))

        PushedAuthorizationRequestService().pushAuthorizationRequest(
            createRequest()
        )

        val body = bodySlot.captured
        assertEquals("openid", body["scope"])
        assertFalse(body.containsKey("authorization_details"))
    }

    @Test
    fun `should send dpop_jkt in the body when provided`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:request_uri:abc"))

        PushedAuthorizationRequestService().pushAuthorizationRequest(
            createRequest(dpopJkt = "jkt-thumbprint")
        )

        assertEquals("jkt-thumbprint", bodySlot.captured["dpop_jkt"])
    }

    @Test
    fun `should omit dpop_jkt from the body when not provided`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:request_uri:abc"))

        PushedAuthorizationRequestService().pushAuthorizationRequest(
            createRequest()
        )

        assertFalse(bodySlot.captured.containsKey("dpop_jkt"))
    }

    @Test
    fun `should merge clientAuthParams into the body`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:request_uri:abc"))

        PushedAuthorizationRequestService().pushAuthorizationRequest(
            createRequest(
                clientAuthParams = mapOf(
                    "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion" to "signed.jwt.value"
                )
            )
        )

        val body = bodySlot.captured
        assertEquals(
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            body["client_assertion_type"]
        )
        assertEquals("signed.jwt.value", body["client_assertion"])
    }

    @Test
    fun `clientAuthParams must not overwrite core params like client_id`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:request_uri:abc"))

        PushedAuthorizationRequestService().pushAuthorizationRequest(
            createRequest(
                clientId = "real-client-id",
                clientAuthParams = mapOf("client_id" to "malicious-id")
            )
        )

        assertEquals("real-client-id", bodySlot.captured["client_id"])
    }

    @Test
    fun `should throw when response has no request_uri`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(null)

        val ex = assertThrows<PushedAuthorizationRequestException> {
            PushedAuthorizationRequestService().pushAuthorizationRequest(
                createRequest()
            )
        }
        assertTrue(ex.message.contains("missing request_uri"))
    }

    @Test
    fun `should wrap server error and propagate issuerErrorCode`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        every {
            NetworkManager.sendRequest(parEndpoint, HttpMethod.POST, any(), capture(bodySlot), any())
        } throws NetworkRequestFailedException(
            "HTTP 401",
            "invalid_client",
            "Client authentication failed",
            null
        )

        val ex = assertThrows<PushedAuthorizationRequestException> {
            PushedAuthorizationRequestService().pushAuthorizationRequest(
                createRequest()
            )
        }
        assertEquals("invalid_client", ex.issuerErrorCode)
        assertEquals("Client authentication failed", ex.issuerErrorDescription)
    }
}
