package io.mosip.vciclient.credentialOffer

import io.mosip.vciclient.proof.ProofBindingContext
import com.google.gson.JsonPrimitive
import io.mosip.vciclient.credential.response.CredentialItem
import io.mockk.coEvery
import io.mockk.mockk
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationMethod
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.constants.OID4VCIVersion
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.preAuthCodeFlow.PreAuthCodeFlowService
import io.mosip.vciclient.proof.CredentialRequestProofs
import io.mosip.vciclient.token.TokenResponse
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

import io.mosip.vciclient.preAuthCodeFlow.CredentialRequestContext
import io.mosip.vciclient.preAuthCodeFlow.PreAuthFlowOptions
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeCredentialRequest

class CredentialOfferFlowHandlerV1Test {
    private val credentialOfferService = mockk<CredentialOfferService>()
    private val issuerMetadataService = mockk<IssuerMetadataService>()
    private val preAuthFlowService = mockk<PreAuthCodeFlowService>()
    private val authorizationCodeFlowService = mockk<AuthorizationCodeFlowService>()

    private val handler = CredentialOfferFlowHandler(
        credentialOfferService = credentialOfferService,
        issuerMetadataService = issuerMetadataService,
        preAuthFlowService = preAuthFlowService,
        authorizationCodeFlowService = authorizationCodeFlowService
    )

    private val clientMetadata = ClientMetadata("client-id", "app://callback")
    private val tokenCallback: suspend (io.mosip.vciclient.token.TokenRequest) -> TokenResponse =
        { TokenResponse("access-token", "Bearer") }
    private val authorizationMethods = listOf(
        AuthorizationMethod.RedirectToWeb(openWebPage = { mapOf("code" to "auth-code") })
    )
    private val issuerMetadataResult = IssuerMetadataResult(
        issuerMetadata = IssuerMetadata(
            credentialIssuer = "https://issuer.example.com",
            credentialEndpoint = "https://issuer.example.com/credential",
            credentialFormat = CredentialFormat.LDP_VC,
            specVersion = OID4VCIVersion.V1
        ),
        raw = mapOf(
            "display" to listOf(mapOf("name" to "Issuer")),
            "credential_configurations_supported" to mapOf(
                "UniversityDegreeCredential" to mapOf(
                    "proof_types_supported" to mapOf(
                        "jwt" to mapOf(
                            "proof_signing_alg_values_supported" to listOf("ES256")
                        )
                    )
                )
            )
        )
    )

    @Test
    fun `downloadCredentials should route pre authorized v1 offers through pre auth service`() = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthCodeGrant(preAuthCode = "pre-auth-code")
            )
        )
        val expectedResponse = CredentialResponse(credentials = listOf(CredentialItem(JsonPrimitive("credential-1"))))

        coEvery { credentialOfferService.fetchCredentialOffer("offer") } returns offer
        coEvery {
            issuerMetadataService.fetchIssuerMetadataResult("https://issuer.example.com", "UniversityDegreeCredential")
        } returns issuerMetadataResult
        coEvery {
            preAuthFlowService.requestCredentials(
                context = any(),
                options = any(),
                getProofs = any(),
            )
        } returns expectedResponse

        val response = handler.downloadCredentials(
            credentialOffer = "offer",
            getProofs = { _ -> CredentialRequestProofs(proofs = listOf("proof-1")) },
            request = CredentialDownloadRequest(
                authorizationCodeOptions = AuthorizationCodeRequestOptions(
                    clientMetadata = clientMetadata,
                    authorizationMethods = authorizationMethods,
                ),
                transactionOptions = CredentialTransactionOptions(
                    getTxCode = null,
                    getTokenResponse = tokenCallback,
                    onCheckIssuerTrust = { _, _ -> true },
                    downloadTimeoutInMillis = 11_000,
                )
            )
        )

        assertEquals(expectedResponse, response)
    }

    @Test
    fun `downloadCredentials should route authorization code v1 offers through auth code service`() = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(
                authorizationCodeGrant = AuthorizationCodeGrant(issuerState = "issuer-state")
            )
        )
        val expectedResponse = CredentialResponse(credentials = listOf(CredentialItem(JsonPrimitive("credential-1"))))

        coEvery { credentialOfferService.fetchCredentialOffer("offer") } returns offer
        coEvery {
            issuerMetadataService.fetchIssuerMetadataResult("https://issuer.example.com", "UniversityDegreeCredential")
        } returns issuerMetadataResult
        coEvery {
            authorizationCodeFlowService.requestCredentials(
                request = any(),
                getProofs = any(),
            )
        } returns expectedResponse

        val response = handler.downloadCredentials(
            credentialOffer = "offer",
            getProofs = { _ -> CredentialRequestProofs(proofs = listOf("proof-1")) },
            request = CredentialDownloadRequest(
                authorizationCodeOptions = AuthorizationCodeRequestOptions(
                    clientMetadata = clientMetadata,
                    authorizationMethods = authorizationMethods,
                    traceabilityId = "trace-1",
                ),
                transactionOptions = CredentialTransactionOptions(
                    getTxCode = null,
                    getTokenResponse = tokenCallback,
                    onCheckIssuerTrust = { _, _ -> true },
                    downloadTimeoutInMillis = 11_000,
                )
            )
        )

        assertEquals(expectedResponse, response)
    }

    @Test
    fun `downloadCredentials should propagate empty credential response from v1 flow`() = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthCodeGrant(preAuthCode = "pre-auth-code")
            )
        )
        val emptyResponse = CredentialResponse(credentials = emptyList())

        coEvery { credentialOfferService.fetchCredentialOffer("offer") } returns offer
        coEvery {
            issuerMetadataService.fetchIssuerMetadataResult("https://issuer.example.com", "UniversityDegreeCredential")
        } returns issuerMetadataResult
        coEvery {
            preAuthFlowService.requestCredentials(any(), any(), any())
        } returns emptyResponse

        val response = handler.downloadCredentials(
            credentialOffer = "offer",
            getProofs = { _ -> CredentialRequestProofs(proofs = listOf("proof-1")) },
            request = CredentialDownloadRequest(
                authorizationCodeOptions = AuthorizationCodeRequestOptions(
                    clientMetadata = clientMetadata,
                    authorizationMethods = authorizationMethods,
                ),
                transactionOptions = CredentialTransactionOptions(
                    getTxCode = null,
                    getTokenResponse = tokenCallback,
                    onCheckIssuerTrust = { _, _ -> true },
                )
            )
        )

        assertEquals(emptyResponse, response)
    }
}
