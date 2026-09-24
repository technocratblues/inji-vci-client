package io.mosip.vciclient.trustedIssuer

import io.mosip.vciclient.proof.ProofBindingContext
import io.mosip.vciclient.proof.CredentialRequestProofMetadata
import com.google.gson.JsonPrimitive
import io.mosip.vciclient.credential.response.CredentialItem
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationMethod
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.constants.OID4VCIVersion
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.credential.response.CredentialResponseDraft13
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.proof.CredentialRequestProofs
import io.mosip.vciclient.token.TokenResponse
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TrustedIssuerFlowHandlerTest {
    private val authService = mockk<AuthorizationCodeFlowService>()
    private val issuerMetadataService = mockk<IssuerMetadataService>()
    private val flowHandler = TrustedIssuerFlowHandler(authService, issuerMetadataService)

    private val credentialIssuer = "https://example.com/issuer"
    private val credentialConfigurationId = "UniversityDegreeCredential"
    private val clientMetadata = ClientMetadata("client-id", "app://callback")
    private val authorizationMethods = listOf(
        AuthorizationMethod.RedirectToWeb(openWebPage = { mapOf("code" to "auth-code") })
    )
    private val tokenResponseCallback: suspend (io.mosip.vciclient.token.TokenRequest) -> TokenResponse =
        { TokenResponse(accessToken = "access-token", tokenType = "Bearer", cNonce = "nonce-123") }

    @Test
    fun `downloadCredentials should delegate v1 issuers to requestCredentials`() = runBlocking {
        val issuerMetadataResult = issuerMetadataResult(specVersion = OID4VCIVersion.V1)
        val expectedResponse = CredentialResponse(
            credentials = listOf(CredentialItem(JsonPrimitive("credential-1"))),
            credentialConfigurationId = credentialConfigurationId,
            credentialIssuer = credentialIssuer
        )

        coEvery {
            issuerMetadataService.fetchIssuerMetadataResult(credentialIssuer, credentialConfigurationId)
        } returns issuerMetadataResult

        coEvery {
            authService.requestCredentials(
                issuerMetadata = issuerMetadataResult.issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = any(),
                getProofs = any(),
                authorizationMethods = authorizationMethods,
                downloadTimeOutInMillis = 10_000,
                proofBindingContext = ProofBindingContext(proofSigningAlgorithmsSupported = listOf("ES256"), cryptographicBindingMethodsSupported = listOf("did:jwk"), proofTypesSupported = listOf("jwt")),
                dpopManager = any()
            )
        } returns expectedResponse

        val response = flowHandler.downloadCredentials(
            credentialIssuer = credentialIssuer,
            credentialConfigurationId = credentialConfigurationId,
            clientMetadata = clientMetadata,
            getTokenResponse = tokenResponseCallback,
            getProofs = { _ -> CredentialRequestProofs(proofs = listOf("proof-1")) },
            authorizationMethods = authorizationMethods,
            downloadTimeoutInMillis = 10_000
        )

        assertEquals(expectedResponse, response)
    }

    @Test
    fun `downloadCredentials should wrap draft13 response into v1 shaped credential response`() = runBlocking {
        val issuerMetadataResult = issuerMetadataResult(specVersion = OID4VCIVersion.DRAFT13)
        val draft13Response = CredentialResponseDraft13(
            credential = JsonPrimitive("credential-1"),
            credentialConfigurationId = credentialConfigurationId,
            credentialIssuer = credentialIssuer
        )

        coEvery {
            issuerMetadataService.fetchIssuerMetadataResult(credentialIssuer, credentialConfigurationId)
        } returns issuerMetadataResult

        coEvery {
            authService.requestCredentialsDraft13(
                issuerMetadata = issuerMetadataResult.issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = any(),
                getProofJwt = any(),
                authorizationMethods = authorizationMethods,
                downloadTimeOutInMillis = 10_000,
                proofBindingContext = ProofBindingContext(proofSigningAlgorithmsSupported = listOf("ES256"), cryptographicBindingMethodsSupported = listOf("did:jwk"), proofTypesSupported = listOf("jwt")),
                dpopManager = any()
            )
        } returns draft13Response

        val response = flowHandler.downloadCredentials(
            credentialIssuer = credentialIssuer,
            credentialConfigurationId = credentialConfigurationId,
            clientMetadata = clientMetadata,
            getTokenResponse = tokenResponseCallback,
            getProofs = { _ -> CredentialRequestProofs(proofs = listOf("proof-1")) },
            authorizationMethods = authorizationMethods,
            downloadTimeoutInMillis = 10_000
        )

        assertEquals(listOf(CredentialItem(JsonPrimitive("credential-1"))), response.credentials)
        assertEquals(credentialConfigurationId, response.credentialConfigurationId)
        assertEquals(credentialIssuer, response.credentialIssuer)
    }

    @Test
    fun `downloadCredentials should fail for draft13 issuer when proofs callback returns empty collection`() {
        val issuerMetadataResult = issuerMetadataResult(specVersion = OID4VCIVersion.DRAFT13)

        coEvery {
            issuerMetadataService.fetchIssuerMetadataResult(credentialIssuer, credentialConfigurationId)
        } returns issuerMetadataResult

        coEvery {
            authService.requestCredentialsDraft13(
                issuerMetadata = issuerMetadataResult.issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = any(),
                getProofJwt = any(),
                authorizationMethods = authorizationMethods,
                downloadTimeOutInMillis = any(),
                proofBindingContext = ProofBindingContext(proofSigningAlgorithmsSupported = listOf("ES256"), cryptographicBindingMethodsSupported = listOf("did:jwk"), proofTypesSupported = listOf("jwt")),
                dpopManager = any()
            )
        } coAnswers {
            @Suppress("UNCHECKED_CAST")
            val getProofJwt = invocation.args[4] as suspend (CredentialRequestProofMetadata) -> String
            getProofJwt(
                CredentialRequestProofMetadata(
                    credentialIssuer = credentialIssuer,
                    nonce = "nonce-123",
                    proofSigningAlgorithmsSupported = listOf("ES256"),
                )
            )
            CredentialResponseDraft13(credential = JsonPrimitive("unused"))
        }

        val exception = assertThrows(DownloadFailedException::class.java) {
            runBlocking {
                flowHandler.downloadCredentials(
                    credentialIssuer = credentialIssuer,
                    credentialConfigurationId = credentialConfigurationId,
                    clientMetadata = clientMetadata,
                    getTokenResponse = tokenResponseCallback,
                    getProofs = { _ -> CredentialRequestProofs(proofs = emptyList()) },
                    authorizationMethods = authorizationMethods
                )
            }
        }

        assertEquals(
            "Failed to download Credential: Draft13 issuer requires a single JWT proof",
            exception.message
        )
    }

    @Test
    fun `downloadCredentials should invoke draft13 request path for draft13 issuer`() = runBlocking {
        val issuerMetadataResult = issuerMetadataResult(specVersion = OID4VCIVersion.DRAFT13)
        val draft13Response = CredentialResponseDraft13(credential = JsonPrimitive("credential-1"))

        coEvery {
            issuerMetadataService.fetchIssuerMetadataResult(credentialIssuer, credentialConfigurationId)
        } returns issuerMetadataResult

        coEvery {
            authService.requestCredentialsDraft13(
                issuerMetadata = issuerMetadataResult.issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = any(),
                getProofJwt = any(),
                authorizationMethods = authorizationMethods,
                downloadTimeOutInMillis = any(),
                proofBindingContext = ProofBindingContext(proofSigningAlgorithmsSupported = listOf("ES256"), cryptographicBindingMethodsSupported = listOf("did:jwk"), proofTypesSupported = listOf("jwt")),
                dpopManager = any()
            )
        } returns draft13Response

        flowHandler.downloadCredentials(
            credentialIssuer = credentialIssuer,
            credentialConfigurationId = credentialConfigurationId,
            clientMetadata = clientMetadata,
            getTokenResponse = tokenResponseCallback,
            getProofs = { _ -> CredentialRequestProofs(proofs = listOf("proof-1", "proof-2")) },
            authorizationMethods = authorizationMethods
        )

        coVerify(exactly = 1) {
            authService.requestCredentialsDraft13(
                issuerMetadata = issuerMetadataResult.issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = any(),
                getProofJwt = any(),
                authorizationMethods = authorizationMethods,
                downloadTimeOutInMillis = any(),
                proofBindingContext = ProofBindingContext(proofSigningAlgorithmsSupported = listOf("ES256"), cryptographicBindingMethodsSupported = listOf("did:jwk"), proofTypesSupported = listOf("jwt")),
                dpopManager = any()
            )
        }
    }

    private fun issuerMetadataResult(specVersion: OID4VCIVersion): IssuerMetadataResult {
        val issuerMetadata = IssuerMetadata(
            credentialIssuer = credentialIssuer,
            credentialEndpoint = "https://example.com/credential",
            credentialFormat = CredentialFormat.LDP_VC,
            specVersion = specVersion
        )

        return IssuerMetadataResult(
            issuerMetadata = issuerMetadata,
            raw = mapOf(
                "credential_configurations_supported" to mapOf(
                    credentialConfigurationId to mapOf(
                        "cryptographic_binding_methods_supported" to listOf("did:jwk"),
                        "proof_types_supported" to mapOf(
                            "jwt" to mapOf(
                                "proof_signing_alg_values_supported" to listOf("ES256")
                            )
                        )
                    )
                )
            )
        )
    }
}
