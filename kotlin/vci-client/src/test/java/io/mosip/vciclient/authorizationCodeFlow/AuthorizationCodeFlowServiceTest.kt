package io.mosip.vciclient.authorizationCodeFlow

import io.mosip.vciclient.proof.ProofBindingContext
import com.google.gson.JsonPrimitive
import io.mosip.vciclient.credential.response.CredentialItem
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.InteractiveAuthorizationHandler
import io.mosip.vciclient.authorizationServer.AuthorizationServerMetadata
import io.mosip.vciclient.authorizationServer.AuthorizationServerResolver
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.credential.request.CredentialRequestExecutor
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.nonce.NonceService
import io.mosip.vciclient.pkce.PKCESessionManager
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class AuthorizationCodeFlowServiceV1Test {
    private val proofBindingContext = ProofBindingContext(
        proofSigningAlgorithmsSupported = listOf("ES256"),
        cryptographicBindingMethodsSupported = listOf("did:jwk"),
        proofTypesSupported = listOf("jwt"),
    )
    private val resolver = mockk<AuthorizationServerResolver>()
    private val tokenService = mockk<TokenService>()
    private val executor = mockk<CredentialRequestExecutor>()
    private val pkceSessionManager = mockk<PKCESessionManager>()
    private val interactiveAuthorizationHandler = mockk<InteractiveAuthorizationHandler>()
    private val nonceService = mockk<NonceService>()

    private val service = AuthorizationCodeFlowService(
        authorizationServerResolver = resolver,
        tokenService = tokenService,
        credentialExecutor = executor,
        pkceSessionManager = pkceSessionManager,
        interactiveAuthorizationHandler = interactiveAuthorizationHandler,
        nonceService = nonceService
    )

    private val issuerMetadata = IssuerMetadata(
        credentialIssuer = "https://issuer.example.com",
        credentialEndpoint = "https://issuer.example.com/credential",
        credentialFormat = CredentialFormat.LDP_VC,
        nonceEndpoint = "https://issuer.example.com/nonce"
    )
    private val clientMetadata = ClientMetadata("client-id", "app://callback")
    private val authorizationMethods = listOf(
        AuthorizationMethod.RedirectToWeb(openWebPage = { mapOf("code" to "auth-code") })
    )
    private val pkceSession = PKCESessionManager.PKCESession(
        codeVerifier = "verifier",
        codeChallenge = "challenge",
        state = "state",
        nonce = "state-nonce"
    )

    @Test
    fun `requestCredentials should fetch nonce and request credential for v1 issuers`() {
        runBlocking {
            val expectedResponse = CredentialResponse(
                credentials = listOf(CredentialItem(JsonPrimitive("credential-1")))
            )

            every { pkceSessionManager.createSession() } returns pkceSession
            coEvery { resolver.resolveForAuthCode(issuerMetadata, null) } returns AuthorizationServerMetadata(
                issuer = "https://auth.example.com",
                tokenEndpoint = "https://auth.example.com/token",
                authorizationEndpoint = "https://auth.example.com/authorize"
            )
            coEvery {
                tokenService.getAccessToken(
                    getTokenResponse = any(),
                    tokenEndpoint = "https://auth.example.com/token",
                    authCode = "auth-code",
                    clientId = "client-id",
                    redirectUri = "app://callback",
                    codeVerifier = "verifier",
                    dpopManager = any()
                )
            } returns TokenResponse("access-token", "Bearer")
            coEvery { nonceService.fetchNonce(issuerMetadata, 15_000, any()) } returns "nonce-123"
            every {
                executor.requestCredential(
                    issuerMetadata = issuerMetadata,
                    credentialConfigurationId = "UniversityDegreeCredential",
                    proofs = any(),
                    accessToken = "access-token",
                    downloadTimeoutInMillis = 15_000,
                    tokenType = any(),
                    dpopManager = any()
                )
            } returns expectedResponse

            val response = service.requestCredentials(
                issuerMetadata = issuerMetadata,
                credentialConfigurationId = "UniversityDegreeCredential",
                clientMetadata = clientMetadata,
                getTokenResponse = { error("token callback should not be used directly") },
                getProofs = { proofRequest ->
                    assertEquals("https://issuer.example.com", proofRequest.credentialIssuer)
                    assertEquals("nonce-123", proofRequest.nonce)
                    assertEquals(listOf("ES256"), proofRequest.proofSigningAlgorithmsSupported)
                    io.mosip.vciclient.proof.CredentialRequestProofs(proofs = listOf("proof-1"))
                },
                authorizationMethods = authorizationMethods,
                downloadTimeOutInMillis = 15_000,
                proofBindingContext = proofBindingContext
            )

            assertEquals(expectedResponse, response)
            coVerify(exactly = 1) { resolver.resolveForAuthCode(issuerMetadata, null) }
            coVerify(exactly = 1) {
                tokenService.getAccessToken(any(), "https://auth.example.com/token", "auth-code", "client-id", "app://callback", "verifier", any())
            }
            io.mockk.coVerify(exactly = 1) { nonceService.fetchNonce(issuerMetadata, 15_000, any()) }
        }
    }

    @Test
    fun `requestCredentials should wrap proof callback failures for v1 issuers`() {
        every { pkceSessionManager.createSession() } returns pkceSession
        coEvery { resolver.resolveForAuthCode(issuerMetadata, null) } returns AuthorizationServerMetadata(
            issuer = "https://auth.example.com",
            tokenEndpoint = "https://auth.example.com/token",
            authorizationEndpoint = "https://auth.example.com/authorize"
        )
        coEvery {
            tokenService.getAccessToken(any(), any(), any(), any(), any(), any(), any())
        } returns TokenResponse("access-token", "Bearer")
        coEvery { nonceService.fetchNonce(issuerMetadata, any(), any()) } returns "nonce-123"

        val exception = assertThrows(DownloadFailedException::class.java) {
            runBlocking {
                service.requestCredentials(
                    issuerMetadata = issuerMetadata,
                    credentialConfigurationId = "UniversityDegreeCredential",
                    clientMetadata = clientMetadata,
                    getTokenResponse = { error("unused") },
                    getProofs = { _ -> throw IllegalStateException("proof generation failed") },
                    authorizationMethods = authorizationMethods,
                    proofBindingContext = proofBindingContext
                )
            }
        }

        assertTrue(exception.message.contains("Failed to obtain proofs from callback"))
        assertEquals("proof generation failed", exception.cause?.message)
    }

    @Test
    fun `requestCredentials should skip nonce and proofs when holder binding is not required`() {
        runBlocking {
            val expectedResponse = CredentialResponse(
                credentials = listOf(CredentialItem(JsonPrimitive("credential-1")))
            )

            every { pkceSessionManager.createSession() } returns pkceSession
            coEvery { resolver.resolveForAuthCode(issuerMetadata, null) } returns AuthorizationServerMetadata(
                issuer = "https://auth.example.com",
                tokenEndpoint = "https://auth.example.com/token",
                authorizationEndpoint = "https://auth.example.com/authorize"
            )
            coEvery {
                tokenService.getAccessToken(any(), any(), any(), any(), any(), any(), any())
            } returns TokenResponse("access-token", "Bearer")
            every {
                executor.requestCredential(
                    issuerMetadata = issuerMetadata,
                    credentialConfigurationId = "UniversityDegreeCredential",
                    proofs = null,
                    accessToken = "access-token",
                    downloadTimeoutInMillis = any(),
                    tokenType = any(),
                    dpopManager = any()
                )
            } returns expectedResponse

            val response = service.requestCredentials(
                issuerMetadata = issuerMetadata,
                credentialConfigurationId = "UniversityDegreeCredential",
                clientMetadata = clientMetadata,
                getTokenResponse = { error("unused") },
                getProofs = { error("proofs callback should not be invoked") },
                authorizationMethods = authorizationMethods,
                proofBindingContext = ProofBindingContext(proofSigningAlgorithmsSupported = listOf("ES256"))
            )

            assertEquals(expectedResponse, response)
            coVerify(exactly = 0) { nonceService.fetchNonce(any(), any(), any()) }
        }
    }
}
