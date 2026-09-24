package io.mosip.vciclient.preAuthCodeFlow

import io.mosip.vciclient.proof.ProofBindingContext
import com.google.gson.JsonPrimitive
import io.mosip.vciclient.credential.response.CredentialItem
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mosip.vciclient.authorizationServer.AuthorizationServerMetadata
import io.mosip.vciclient.authorizationServer.AuthorizationServerResolver
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.credential.request.CredentialRequestExecutor
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.credentialOffer.CredentialOfferGrants
import io.mosip.vciclient.credentialOffer.PreAuthCodeGrant
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.nonce.NonceService
import io.mosip.vciclient.proof.CredentialRequestProofs
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class PreAuthCodeFlowServiceV1Test {
    private val proofBindingContext = ProofBindingContext(
        proofSigningAlgorithmsSupported = listOf("ES256"),
        cryptographicBindingMethodsSupported = listOf("did:jwk"),
        proofTypesSupported = listOf("jwt"),
    )
    private val resolver = mockk<AuthorizationServerResolver>()
    private val tokenService = mockk<TokenService>()
    private val executor = mockk<CredentialRequestExecutor>()
    private val nonceService = mockk<NonceService>()

    private val service = PreAuthCodeFlowService(
        authServerResolver = resolver,
        tokenService = tokenService,
        credentialExecutor = executor,
        nonceService = nonceService
    )

    private val issuerMetadata = IssuerMetadata(
        credentialIssuer = "https://issuer.example.com",
        credentialEndpoint = "https://issuer.example.com/credential",
        credentialFormat = CredentialFormat.LDP_VC,
        nonceEndpoint = "https://issuer.example.com/nonce"
    )
    private val offer = CredentialOffer(
        credentialIssuer = "https://issuer.example.com",
        credentialConfigurationIds = listOf("UniversityDegreeCredential"),
        grants = CredentialOfferGrants(
            preAuthorizedGrant = PreAuthCodeGrant(preAuthCode = "pre-auth-code")
        )
    )

    @Test
    fun `requestCredentials should fetch nonce and request v1 credential for pre auth offers`() = runBlocking {
        val expectedResponse = CredentialResponse(credentials = listOf(CredentialItem(JsonPrimitive("credential-1"))))

        coEvery { resolver.resolveForPreAuth(issuerMetadata, offer) } returns AuthorizationServerMetadata(
            issuer = "https://auth.example.com",
            tokenEndpoint = "https://auth.example.com/token"
        )
        coEvery {
            tokenService.getAccessToken(
                getTokenResponse = any(),
                tokenEndpoint = "https://auth.example.com/token",
                preAuthCode = "pre-auth-code",
                txCode = null,
                dpopManager = any()
            )
        } returns TokenResponse("access-token", "Bearer")
        coEvery { nonceService.fetchNonce(issuerMetadata, 12_000, any()) } returns "nonce-123"
        every {
            executor.requestCredential(
                issuerMetadata = issuerMetadata,
                credentialConfigurationId = "UniversityDegreeCredential",
                proofs = any(),
                accessToken = "access-token",
                downloadTimeoutInMillis = 12_000,
                tokenType = any(),
                dpopManager = any()
            )
        } returns expectedResponse

        val response = service.requestCredentials(
            issuerMetadata = issuerMetadata,
            proofBindingContext = proofBindingContext,
            getTokenResponse = { error("unused") },
            getProofs = { proofRequest ->
                assertEquals("https://issuer.example.com", proofRequest.credentialIssuer)
                assertEquals("nonce-123", proofRequest.nonce)
                assertEquals(listOf("ES256"), proofRequest.proofSigningAlgorithmsSupported)
                CredentialRequestProofs(proofs = listOf("proof-1"))
            },
            credentialConfigurationId = "UniversityDegreeCredential",
            downloadTimeoutInMillis = 12_000,
            offer = offer
        )

        assertEquals(expectedResponse, response)
    }

    @Test
    fun `requestCredentials should wrap proof callback failures for v1 pre auth offers`() {
        coEvery { resolver.resolveForPreAuth(issuerMetadata, offer) } returns AuthorizationServerMetadata(
            issuer = "https://auth.example.com",
            tokenEndpoint = "https://auth.example.com/token"
        )
        coEvery { tokenService.getAccessToken(getTokenResponse = any(), tokenEndpoint = any(), preAuthCode = any(), txCode = any(), dpopManager = any()) } returns TokenResponse("access-token", "Bearer")
        coEvery { nonceService.fetchNonce(issuerMetadata, any(), any()) } returns "nonce-123"

        val exception = assertThrows(DownloadFailedException::class.java) {
            runBlocking {
                service.requestCredentials(
                    issuerMetadata = issuerMetadata,
                    proofBindingContext = proofBindingContext,
                    getTokenResponse = { error("unused") },
                    getProofs = { _ -> throw IllegalArgumentException("proof generation failed") },
                    credentialConfigurationId = "UniversityDegreeCredential",
                    offer = offer
                )
            }
        }

        assertTrue(exception.message.contains("Failed to obtain proofs from callback"))
        assertEquals("proof generation failed", exception.cause?.message)
    }

    @Test
    fun `requestCredentials should skip nonce and proofs when holder binding is not required`() = runBlocking {
        val expectedResponse = CredentialResponse(credentials = listOf(CredentialItem(JsonPrimitive("credential-1"))))

        coEvery { resolver.resolveForPreAuth(issuerMetadata, offer) } returns AuthorizationServerMetadata(
            issuer = "https://auth.example.com",
            tokenEndpoint = "https://auth.example.com/token"
        )
        coEvery { tokenService.getAccessToken(getTokenResponse = any(), tokenEndpoint = any(), preAuthCode = any(), txCode = any(), dpopManager = any()) } returns TokenResponse("access-token", "Bearer")
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
            proofBindingContext = ProofBindingContext(proofSigningAlgorithmsSupported = listOf("ES256")),
            getTokenResponse = { error("unused") },
            getProofs = { error("proofs callback should not be invoked") },
            credentialConfigurationId = "UniversityDegreeCredential",
            offer = offer
        )

        assertEquals(expectedResponse, response)
        coVerify(exactly = 0) { nonceService.fetchNonce(any(), any(), any()) }
    }
}
