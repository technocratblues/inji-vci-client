package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.presentationDuringIssuance

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.verify
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.wallet.Credential
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request.AuthorizationRequestData
import io.mosip.vciclient.exception.InteractiveAuthorizationException
import io.mosip.vciclient.networkManager.NetworkManager
import io.mosip.vciclient.networkManager.NetworkResponse
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class PresentationDuringIssuanceAuthorizationMethodServiceTest {

    private lateinit var fakeAuthRequest: AuthorizationRequest
    private lateinit var mockOvp: OpenID4VP

    @Before
    fun setup() {
        mockkObject(NetworkManager)

        mockOvp = mockk(relaxed = true)

        fakeAuthRequest = AuthorizationPresentationExchangeRequest(
            clientId = "https://trusted.com",
            redirectUri = "",
            responseType = "vp_token",
            state = "",
            nonce = "",
            responseMode = "iar-post",
            responseUri = null,
            walletNonce = "",
            clientMetadata = null,
            presentationDefinition = PresentationDefinition(
                id = "pd-id",
                inputDescriptors = emptyList()
            )
        )

        // ✅ IMPORTANT: mock positionally (avoid overload + named args mismatch)
        coEvery {
            mockOvp.authenticateVerifier(
                authorizationRequest = any<Map<String, Any>>(),
            )
        } returns fakeAuthRequest

        coEvery { mockOvp.constructUnsignedVPToken(any()) } returns emptyList()
        coEvery { mockOvp.constructVPResponse(any()) } returns emptyMap()
        every { mockOvp.constructErrorInfo(any()) } returns mapOf("error" to "access_denied")

        every { NetworkManager.sendRequest(any(), any(), any(), any()) } returns
                NetworkResponse("""{"status":"error"}""", null)
    }

    private fun validRequest() =
        PresentationDuringIssuanceRequestData(
            ovpRequest = mapOf("issuer" to "https://trusted.com"),
            iar = "https://issuer.com",
            authSession = "auth-session"
        )

    private fun validCredentialMap() =
        mapOf(
            "id1" to listOf(
                Credential(
                    format = FormatType.LDP_VC,
                    data = """{ "credentialSubject": { "id": "did:example:123" } }""",
                    credentialId = "c1"
                )
            )
        )

    // ------------------------------------------------------------------------


    @Test
    fun `should throw when request type is invalid`() = runTest {
        val handler = PresentationDuringIssuanceAuthorizationMethodService(
            selectCredentialsForPresentation = { emptyMap() },
            signVerifiablePresentation = { emptyList() },
            openid4vpWalletConfig = WalletConfig(),
            traceabilityId = "test-trace-id",
            openId4vp = mockOvp,
        )

        assertThrows<InteractiveAuthorizationException> {
            handler.authorizeUser(AuthorizationRequestData())
        }
    }

    @Test
    fun `should use injected OVP instance`() = runTest {
        val injectedOvp = mockk<OpenID4VP>(relaxed = true)
        coEvery { injectedOvp.authenticateVerifier(any<Map<String, Any>>()) } returns fakeAuthRequest
        every { injectedOvp.constructErrorInfo(any()) } returns mapOf("error" to "access_denied")

        val handler = PresentationDuringIssuanceAuthorizationMethodService(
            selectCredentialsForPresentation = { emptyMap() },
            signVerifiablePresentation = { emptyList() },
            openid4vpWalletConfig = WalletConfig(isPresentationDefinitionUriSupported = false),
            traceabilityId = "test-trace-id",
            openId4vp = injectedOvp,
        )

        handler.authorizeUser(validRequest())

        coVerify(exactly = 1) {
            injectedOvp.authenticateVerifier(any<Map<String, Any>>())
        }
    }

    @Test
    fun `should delegate request uri validation and accept iar post jwt mode`() = runTest {
        val requestByReference = mapOf(
            "request_uri" to "https://verifier.example.com/request/123"
        )
        val normalizedRequest = authorizationRequest(responseMode = "iar-post.jwt")
        coEvery {
            mockOvp.authenticateVerifier(requestByReference)
        } returns normalizedRequest

        var selectedRequest: AuthorizationRequest? = null
        val handler = PresentationDuringIssuanceAuthorizationMethodService(
            selectCredentialsForPresentation = {
                selectedRequest = it
                emptyMap()
            },
            signVerifiablePresentation = { emptyList() },
            openid4vpWalletConfig = WalletConfig(),
            traceabilityId = "test-trace-id",
            openId4vp = mockOvp,
        )

        handler.authorizeUser(
            validRequest().copy(ovpRequest = requestByReference)
        )

        coVerify(exactly = 1) {
            mockOvp.authenticateVerifier(requestByReference)
        }
        Assert.assertSame(normalizedRequest, selectedRequest)
    }

    @Test
    fun `should successfully authorize and return success response`() = runTest {
        coEvery { mockOvp.constructUnsignedVPToken(any()) } returns listOf(
             UnsignedVPToken(id = "id1",FormatType.LDP_VC, "k1","ES256", "unsigned".toByteArray())
        )

        coEvery { mockOvp.constructVPResponse(any()) } returns mapOf("vp_token" to "signed")

        every { NetworkManager.sendRequest(any(), any(), any(), any()) } returns NetworkResponse(
            """{
              "status":"success",
              "code":"auth-code-123",
              "auth_session":"auth-session"
            }""",
            null
        )

        val handler = PresentationDuringIssuanceAuthorizationMethodService(
            selectCredentialsForPresentation = { validCredentialMap() },
            signVerifiablePresentation = {
                listOf(
                    VPTokenSigningResult(
                        "id1",
                        signedData = "signed".toByteArray(),
                    )
                )
            },
            openid4vpWalletConfig = WalletConfig(),
            traceabilityId = "test-trace-id",
            openId4vp = mockOvp,
        )

        val result = handler.authorizeUser(validRequest())

        Assert.assertEquals("success", result.status)
        Assert.assertEquals("auth-code-123", result.authorizationCode)

        coVerify(exactly = 1) {
            mockOvp.authenticateVerifier(
                authorizationRequest = any<Map<String, Any>>(),
            )
        }
        coVerify(exactly = 1) { mockOvp.constructUnsignedVPToken(any()) }
        coVerify(exactly = 1) { mockOvp.constructVPResponse(any()) }
    }

    @Test
    fun `should post VP error response when user selects no credentials`() = runTest {

        val handler = PresentationDuringIssuanceAuthorizationMethodService(
            selectCredentialsForPresentation = { emptyMap() },
            signVerifiablePresentation = { emptyList() },
            openid4vpWalletConfig = WalletConfig(),
            traceabilityId = "test-trace-id",
            openId4vp = mockOvp,
        )

        handler.authorizeUser(validRequest())

        verify(exactly = 1) { NetworkManager.sendRequest(any(), any(), any(), any()) }

        coVerify(exactly = 0) { mockOvp.constructUnsignedVPToken(any()) }
        coVerify(exactly = 0) { mockOvp.constructVPResponse(any()) }
    }

    @Test
    fun `should post error response when normalized response mode is unsupported`() = runTest {
        coEvery {
            mockOvp.authenticateVerifier(any<Map<String, Any>>())
        } returns authorizationRequest(responseMode = "direct_post")

        val handler = PresentationDuringIssuanceAuthorizationMethodService(
            selectCredentialsForPresentation = {
                Assert.fail("Credential selection must not run for an unsupported response mode")
                emptyMap()
            },
            signVerifiablePresentation = { emptyList() },
            openid4vpWalletConfig = WalletConfig(),
            traceabilityId = "test-trace-id",
            openId4vp = mockOvp,
        )

        handler.authorizeUser(validRequest())

        verify(exactly = 1) {
            mockOvp.constructErrorInfo(
                match { it.message == "response_mode must be 'iar-post', 'iar-post.jwt', 'iae_post' or 'iae_post.jwt'" }
            )
        }
        coVerify(exactly = 0) { mockOvp.constructUnsignedVPToken(any()) }
    }
    
    @Test
    fun `should throw when network post fails`() = runTest {
        every {
            NetworkManager.sendRequest(
                any(),
                any(),
                any(),
                any()
            )
        } throws RuntimeException("boom")

        val handler = PresentationDuringIssuanceAuthorizationMethodService(
            selectCredentialsForPresentation = { validCredentialMap() },
            signVerifiablePresentation = { emptyList() },
            openid4vpWalletConfig = WalletConfig(),
            traceabilityId = "test-trace-id",
            openId4vp = mockOvp,
        )

        assertThrows<InteractiveAuthorizationException> {
            handler.authorizeUser(validRequest())
        }
    }

    @Test
    fun `should throw when issuer response deserialization fails`() = runTest {
        every { NetworkManager.sendRequest(any(), any(), any(), any()) } returns
                NetworkResponse(""""not":"a-valid-AuthorizationResponse" }""", null)

        val handler = PresentationDuringIssuanceAuthorizationMethodService(
            selectCredentialsForPresentation = { validCredentialMap() },
            signVerifiablePresentation = { emptyList() },
            openid4vpWalletConfig = WalletConfig(),
            traceabilityId = "test-trace-id",
            openId4vp = mockOvp,
        )

        assertThrows<InteractiveAuthorizationException> {
            handler.authorizeUser(validRequest())
        }
    }

    private fun authorizationRequest(
        responseType: String = "vp_token",
        responseMode: String? = "iar-post"
    ) = AuthorizationPresentationExchangeRequest(
        clientId = "https://trusted.com",
        redirectUri = "",
        responseType = responseType,
        state = "",
        nonce = "",
        responseMode = responseMode,
        responseUri = null,
        walletNonce = "",
        clientMetadata = null,
        presentationDefinition = PresentationDefinition(
            id = "pd-id",
            inputDescriptors = emptyList()
        )
    )
}
