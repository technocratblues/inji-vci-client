package io.mosip.vciclient.authorizationCodeFlow

import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkClass
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationMethod
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.InteractiveAuthorizationHandler
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.response.AuthorizationResponse
import io.mosip.vciclient.authorizationServer.AuthorizationServerMetadata
import io.mosip.vciclient.authorizationServer.AuthorizationServerResolver
import io.mosip.vciclient.authorizationServer.AuthorizationUrlBuilder
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.constants.AuthorizeUserCallback
import io.mosip.vciclient.constants.ProofJwtCallback
import io.mosip.vciclient.constants.TokenResponseCallback
import io.mosip.vciclient.credential.request.CredentialRequestExecutor
import io.mosip.vciclient.credential.response.CredentialResponseDraft13
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InteractiveAuthorizationException
import io.mosip.vciclient.exception.InvalidDataProvidedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.pkce.PKCESessionManager
import io.mosip.vciclient.pkce.PKCESessionManager.PKCESession
import io.mosip.vciclient.proof.jwt.JWTProof
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class AuthorizationCodeFlowServiceTest {
    private val downloadTimeout: Long = 5000L
    private val mockCredentialResponse = mockk<CredentialResponseDraft13>()
    private val resolvedIssuerMetadata = mockk<IssuerMetadata>(relaxed = true) {
        every { scope } returns "openid"
    }
    private val clientMetadata = ClientMetadata("client-id", "app://callback")
    private val credentialOffer = mockk<CredentialOffer>()
    private val credentialConfigurationId = "UniversityDegreeCredential"
    private val pkceSession = PKCESession("verifier", "challenge", "state", "nonce")

    private lateinit var authorizeUser: AuthorizeUserCallback
    private lateinit var authorizationMethod: AuthorizationMethod
    private lateinit var getProofJwt: ProofJwtCallback
    private lateinit var getTokenResponse: TokenResponseCallback


    @Before
    fun setup() {
        mockkObject(Util)
        every { Util.getLogTag(any(), null) } returns "mocked-tag"

        mockkConstructor(PKCESessionManager::class)
        mockkConstructor(CredentialRequestExecutor::class)
        mockkConstructor(AuthorizationServerResolver::class)
        mockkObject(AuthorizationUrlBuilder)
        mockkConstructor(TokenService::class)
        mockkConstructor(CredentialRequestExecutor::class)
        mockkConstructor(JWTProof::class)

        every { anyConstructed<PKCESessionManager>().createSession() } returns pkceSession
        every {
            anyConstructed<CredentialRequestExecutor>().requestCredentialDraft13(
                any(),
                any(),
                any(),
                any(),
                any()
            )
        } returns mockCredentialResponse

        coEvery {
            anyConstructed<AuthorizationServerResolver>().resolveForAuthCode(
                any(),
                any()
            )
        } returns mockk<AuthorizationServerMetadata> {
            every { authorizationEndpoint } returns "https://auth.example.com"
            every { tokenEndpoint } returns "https://token.example.com"
            every { interactiveAuthorizationEndpoint } returns null
            every { requireInteractiveAuthorizationRequest } returns false
        }

        every {
            AuthorizationUrlBuilder.build(
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any()
            )
        } returns "https://auth.example.com/authorize"

        coEvery {
            anyConstructed<TokenService>().getAccessToken(any(), any(), any(), any(), any(), any())
        } returns TokenResponse("mockAccessToken", "jwt", expiresIn = 3600, cNonce = "mockCNonce")

        every {
            anyConstructed<JWTProof>().jwt
        } returns "mock.jwt.proof"

        every {
            anyConstructed<CredentialRequestExecutor>().requestCredentialDraft13(
                any(),
                any(),
                any(),
                any()
            )
        } returns mockCredentialResponse

        authorizeUser = { _ -> "mockAuthCode" }
        authorizationMethod = AuthorizationMethod.RedirectToWeb(
            openWebPage = {
                val code = authorizeUser.invoke("dummy-endpoint")
                mapOf(
                    "code" to code,
                )
            }
        )
        getProofJwt = { _, _, _ -> "mock.jwt.proof" }
        getTokenResponse = { _ -> TokenResponse("accessToken", "accessToken") }
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `should return credential when flow is successful via non-interactive authorization flow`() =
        runBlocking {
            val result = AuthorizationCodeFlowService().requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                credentialOffer = credentialOffer,
                downloadTimeOutInMillis = downloadTimeout,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = listOf(authorizationMethod),
            )

            assertEquals(mockCredentialResponse, result)
        }


    @Test
    fun `should throw when token service fails`() {
        runBlocking {
            coEvery {
                anyConstructed<TokenService>().getAccessToken(
                    any(),
                    any(),
                    any(),
                    any(),
                    any(),
                    any()
                )
            } throws Exception("Token service failure")

            val downloadFailureException = assertThrows<DownloadFailedException> {
                AuthorizationCodeFlowService().requestCredentialsDraft13(
                    issuerMetadata = resolvedIssuerMetadata,
                    credentialConfigurationId = credentialConfigurationId,
                    clientMetadata = clientMetadata,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    credentialOffer = credentialOffer,
                    downloadTimeOutInMillis = downloadTimeout,
                    jwtProofAlgorithmsSupported = listOf("ES256"),
                    authorizationMethods = listOf(authorizationMethod),
                )
            }

            assertEquals(
                "Failed to download Credential: Failed to exchange authorization code for access token at : Token service failure",
                downloadFailureException.message
            )
        }
    }

    @Test
    fun `should return credential via interactive flow when interactive endpoint is present`() =
        runBlocking {
            coEvery {
                anyConstructed<AuthorizationServerResolver>().resolveForAuthCode(any(), any())
            } returns mockk<AuthorizationServerMetadata> {
                every { authorizationEndpoint } returns "https://auth.example.com"
                every { tokenEndpoint } returns "https://token.example.com"
                every { interactiveAuthorizationEndpoint } returns "https://auth.example.com/interactive"
             every { requireInteractiveAuthorizationRequest } returns false
            }


            val mockInteractiveAuthHandler = mockkClass(InteractiveAuthorizationHandler::class)

            coEvery {
                mockInteractiveAuthHandler.handle(
                    any(),
                    any(),
                    any(),
                    any(),
                    any(),
                )
            } returns AuthorizationResponse("mockAuthCode", "success")


            val result =
                AuthorizationCodeFlowService(interactiveAuthorizationHandler = mockInteractiveAuthHandler).requestCredentialsDraft13(
                    issuerMetadata = resolvedIssuerMetadata,
                    credentialConfigurationId = credentialConfigurationId,
                    clientMetadata = clientMetadata,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    credentialOffer = credentialOffer,
                    downloadTimeOutInMillis = downloadTimeout,
                    jwtProofAlgorithmsSupported = listOf("ES256"),
                    authorizationMethods = listOf(authorizationMethod),
                )
            assertEquals(mockCredentialResponse, result)
        }

    @Test
    fun `should throw when authorization server resolution fails`() = runBlocking {
        coEvery {
            anyConstructed<AuthorizationServerResolver>().resolveForAuthCode(any(), any())
        } throws RuntimeException("resolver failure")

        val ex = assertThrows<DownloadFailedException> {
            AuthorizationCodeFlowService().requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = listOf(authorizationMethod),
            )
        }

        assertTrue(
            ex.message.contains("Failed to resolve authorization server metadata")
        )
    }

    @Test
    fun `should throw when token endpoint is missing`() = runBlocking {
        coEvery {
            anyConstructed<AuthorizationServerResolver>().resolveForAuthCode(any(), any())
        } returns mockk {
            every { authorizationEndpoint } returns "https://auth.example.com"
            every { tokenEndpoint } returns null
            every { interactiveAuthorizationEndpoint } returns null
             every { requireInteractiveAuthorizationRequest } returns false
        }

        every { resolvedIssuerMetadata.tokenEndpoint } returns null

        val ex = assertThrows<DownloadFailedException> {
            AuthorizationCodeFlowService().requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = listOf(authorizationMethod),
            )
        }

        assertTrue(ex.message.contains("Missing token endpoint"))
    }

    @Test
    fun `should throw when interactive authorization does not return code`() = runBlocking {
        coEvery {
            anyConstructed<AuthorizationServerResolver>().resolveForAuthCode(any(), any())
        } returns mockk {
            every { authorizationEndpoint } returns "https://auth.example.com"
            every { interactiveAuthorizationEndpoint } returns "https://auth.example.com/interactive"
            every { tokenEndpoint } returns "https://token.example.com"
            every { requireInteractiveAuthorizationRequest } returns false
        }

        val mockHandler = mockkClass(InteractiveAuthorizationHandler::class)
        coEvery {
            mockHandler.handle(any(), any(), any(), any(), any())
        } returns AuthorizationResponse(
            authorizationCode = null,
            status = "error",
            error = "access_denied",
            errorDescription = "user rejected"
        )

        val ex = assertThrows<DownloadFailedException> {
            AuthorizationCodeFlowService(
                interactiveAuthorizationHandler = mockHandler
            ).requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = mockk(relaxed = true)
            )
        }
        assertTrue(ex.message.contains("code not received"))
    }

    @Test
    fun `should throw when no authorizeUser callback is provided`() = runBlocking {
        val ex = assertThrows<DownloadFailedException> {
            AuthorizationCodeFlowService().requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = emptyList(),
            )
        }

        assertTrue(
            ex.message.contains("No authorization method available")
        )
    }

    @Test
    fun `should throw when proof jwt callback fails`() = runBlocking {
        val failingProofJwt: ProofJwtCallback = { _, _, _ ->
            throw RuntimeException("signing failed")
        }

        val ex = assertThrows<DownloadFailedException> {
            AuthorizationCodeFlowService().requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = failingProofJwt,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = listOf(authorizationMethod),
            )
        }

        assertTrue(
            ex.message.contains("Failed to obtain proof JWT")
        )
    }

    @Test
    fun `should throw when credential request returns null`() = runBlocking {
        every {
            anyConstructed<CredentialRequestExecutor>().requestCredentialDraft13(
                any(), any(), any(), any(), any()
            )
        } returns null

        val ex = assertThrows<DownloadFailedException> {
            AuthorizationCodeFlowService().requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = listOf(authorizationMethod),
            )
        }

        assertTrue(ex.message.contains("Credential request returned null"))
    }

    @Test
    fun `should wrap resolver client exception details`() = runBlocking {
        coEvery {
            anyConstructed<AuthorizationServerResolver>().resolveForAuthCode(any(), any())
        } throws InvalidDataProvidedException(
            message = "issuer metadata missing",
            issuerErrorCode = "invalid_request",
            issuerErrorDescription = "credential issuer missing"
        )

        val ex = assertThrows<DownloadFailedException> {
            AuthorizationCodeFlowService().requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                credentialOffer = credentialOffer,
                downloadTimeOutInMillis = downloadTimeout,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = listOf(authorizationMethod),
            )
        }

        assertEquals("invalid_request", ex.issuerErrorCode)
        assertEquals("credential issuer missing", ex.issuerErrorDescription)
        assertTrue(ex.message.contains("Failed to resolve authorization server metadata"))
    }

    @Test
    fun `should fallback to authorization endpoint when interactive flow returns missing_interaction_type`() = runBlocking {
        coEvery {
            anyConstructed<AuthorizationServerResolver>().resolveForAuthCode(any(), any())
        } returns mockk {
            every { authorizationEndpoint } returns "https://auth.example.com"
            every { tokenEndpoint } returns "https://token.example.com"
            every { interactiveAuthorizationEndpoint } returns "https://auth.example.com/interactive"
             every { requireInteractiveAuthorizationRequest } returns false
        }

        val mockHandler = mockkClass(InteractiveAuthorizationHandler::class)
        coEvery {
            mockHandler.handle(any(), any(), any(), any(), any(), any())
        } returns AuthorizationResponse(
            authorizationCode = null,
            status = "error",
            error = "missing_interaction_type",
            errorDescription = "interaction type not supported"
        )

        val result = AuthorizationCodeFlowService(
            interactiveAuthorizationHandler = mockHandler
        ).requestCredentialsDraft13(
            issuerMetadata = resolvedIssuerMetadata,
            credentialConfigurationId = credentialConfigurationId,
            clientMetadata = clientMetadata,
            getTokenResponse = getTokenResponse,
            getProofJwt = getProofJwt,
            jwtProofAlgorithmsSupported = listOf("ES256"),
            authorizationMethods = listOf(authorizationMethod),
        )

        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should wrap interactive authorization client exception details`() = runBlocking {
        coEvery {
            anyConstructed<AuthorizationServerResolver>().resolveForAuthCode(any(), any())
        } returns mockk {
            every { authorizationEndpoint } returns "https://auth.example.com"
            every { tokenEndpoint } returns "https://token.example.com"
            every { interactiveAuthorizationEndpoint } returns "https://auth.example.com/interactive"
        every { requireInteractiveAuthorizationRequest } returns false
        }

        val mockHandler = mockkClass(InteractiveAuthorizationHandler::class)

        coEvery {
            mockHandler.handle(any(), any(), any(), any(), any(), any())
        } throws InteractiveAuthorizationException(
            message = "interaction rejected",
            issuerErrorCode = "access_denied",
            issuerErrorDescription = "user cancelled"
        )

        val ex = assertThrows<DownloadFailedException> {
            AuthorizationCodeFlowService(
                interactiveAuthorizationHandler = mockHandler
            ).requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                credentialOffer = credentialOffer,
                downloadTimeOutInMillis = downloadTimeout,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = listOf(authorizationMethod),
            )
        }

        assertEquals("access_denied", ex.issuerErrorCode)
        assertEquals("user cancelled", ex.issuerErrorDescription)
        assertTrue(ex.message.contains("Interactive authorization failed at endpoint"))
    }

    @Test
    fun `should not fallback and throw when interactive flow fails with different error`() = runBlocking {
        coEvery {
            anyConstructed<AuthorizationServerResolver>().resolveForAuthCode(any(), any())
        } returns mockk {
            every { authorizationEndpoint } returns "https://auth.example.com"
            every { tokenEndpoint } returns "https://token.example.com"
            every { interactiveAuthorizationEndpoint } returns "https://auth.example.com/interactive"
        every { requireInteractiveAuthorizationRequest } returns false
        }


        val mockHandler = mockkClass(InteractiveAuthorizationHandler::class)

        coEvery {
            mockHandler.handle(any(), any(), any(), any(), any(), any())
        } returns AuthorizationResponse(
            authorizationCode = null,
            status = "error",
            error = "access_denied",
            errorDescription = "user denied"
        )

        val ex = assertThrows<DownloadFailedException> {
            AuthorizationCodeFlowService(
                interactiveAuthorizationHandler = mockHandler
            ).requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = listOf(authorizationMethod),
            )
        }

        assertTrue(ex.message.contains("code not received"))
        assertEquals("access_denied", ex.issuerErrorCode)
        assertEquals("user denied", ex.issuerErrorDescription)
    }

    @Test
    fun `should wrap interactive authorization runtime failures`() = runBlocking {
        coEvery {
            anyConstructed<AuthorizationServerResolver>().resolveForAuthCode(any(), any())
        } returns mockk {
            every { authorizationEndpoint } returns "https://auth.example.com"
            every { tokenEndpoint } returns "https://token.example.com"
            every { interactiveAuthorizationEndpoint } returns "https://auth.example.com/interactive"
        every { requireInteractiveAuthorizationRequest } returns false
        }

        val mockHandler = mockkClass(InteractiveAuthorizationHandler::class)
        coEvery {
            mockHandler.handle(any(), any(), any(), any(), any(), any())
        } throws RuntimeException("interactive flow crashed")

        val ex = assertThrows<DownloadFailedException> {
            AuthorizationCodeFlowService(
                interactiveAuthorizationHandler = mockHandler
            ).requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                credentialOffer = credentialOffer,
                downloadTimeOutInMillis = downloadTimeout,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = listOf(authorizationMethod),
            )
        }

        assertTrue(ex.message.contains("Interactive authorization failed at endpoint"))
        assertTrue(ex.message.contains("interactive flow crashed"))
    }

    @Test
    fun `should wrap credential executor client exception details`() = runBlocking {
        every {
            anyConstructed<CredentialRequestExecutor>().requestCredentialDraft13(
                any(),
                any(),
                any(),
                any(),
                any()
            )
        } throws InvalidDataProvidedException(
            message = "proof missing",
            issuerErrorCode = "invalid_proof",
            issuerErrorDescription = "proof callback returned invalid JWT"
        )

        val ex = assertThrows<DownloadFailedException> {
            AuthorizationCodeFlowService().requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                credentialOffer = credentialOffer,
                downloadTimeOutInMillis = downloadTimeout,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = listOf(authorizationMethod),
            )
        }

        assertEquals("invalid_proof", ex.issuerErrorCode)
        assertEquals("proof callback returned invalid JWT", ex.issuerErrorDescription)
        assertEquals(
            "Failed to download Credential: Required details not provided proof missing",
            ex.message
        )
    }

    @Test
    fun `should wrap unexpected credential executor failures`() = runBlocking {
        every {
            anyConstructed<CredentialRequestExecutor>().requestCredentialDraft13(
                any(),
                any(),
                any(),
                any(),
                any()
            )
        } throws RuntimeException("credential request crashed")

        val ex = assertThrows<DownloadFailedException> {
            AuthorizationCodeFlowService().requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                credentialOffer = credentialOffer,
                downloadTimeOutInMillis = downloadTimeout,
                jwtProofAlgorithmsSupported = listOf("ES256"),
                authorizationMethods = listOf(authorizationMethod),
            )
        }

        assertEquals(
            "Failed to download Credential: Download failed via authorization code flow: credential request crashed",
            ex.message
        )
    }

    @Test
    fun `should append redirect to web authorization method when authorize user callback is provided`() =
        runBlocking {
            val service = AuthorizationCodeFlowService()
            val methods = service.normalizeAuthorizationMethods(
                authorizeUser = { authUrl ->
                    assertEquals("https://issuer.example.com/authorize", authUrl)
                    "auth-code"
                },
                authorizationMethods = listOf(authorizationMethod)
            )

            assertEquals(2, methods.size)
            val redirectMethod = methods.last() as AuthorizationMethod.RedirectToWeb
            val response = redirectMethod.openWebPage.invoke("https://issuer.example.com/authorize")

            assertEquals("auth-code", response["code"])
        }

@Test
fun `should throw when interactive authorization is required but endpoint is missing`() = runBlocking {
    coEvery {
        anyConstructed<AuthorizationServerResolver>().resolveForAuthCode(any(), any())
    } returns mockk {
        every { authorizationEndpoint } returns "https://auth.example.com"
        every { tokenEndpoint } returns "https://token.example.com"
        every { interactiveAuthorizationEndpoint } returns null
        every { requireInteractiveAuthorizationRequest } returns true
    }

    val exception = assertThrows<DownloadFailedException> {
        AuthorizationCodeFlowService().requestCredentialsDraft13(
            issuerMetadata = resolvedIssuerMetadata,
            credentialConfigurationId = credentialConfigurationId,
            clientMetadata = clientMetadata,
            getTokenResponse = getTokenResponse,
            getProofJwt = getProofJwt,
            jwtProofAlgorithmsSupported = listOf("ES256"),
            authorizationMethods = listOf(authorizationMethod)
        )
    }

  assertTrue(
    exception.message!!.contains("Missing interactive authorization endpoint")
)
}
}