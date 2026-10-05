package io.mosip.vciclient

import com.google.gson.JsonPrimitive
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationMethod
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.ProofsCallback
import io.mosip.vciclient.credential.response.CredentialItem
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.credentialOffer.CredentialOfferFlowHandler
import io.mosip.vciclient.exception.IssuerMetadataFetchException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.proof.CredentialRequestProofs
import io.mosip.vciclient.trustedIssuer.TrustedIssuerFlowHandler
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class VCIClientTest {

    private val mockCredentialResponse = CredentialResponse(
        credentials = listOf(CredentialItem(JsonPrimitive("dummy-credential")))
    )

    private lateinit var getProofs: ProofsCallback

    @Before
    fun setup() {
        mockkConstructor(CredentialOfferFlowHandler::class)
        mockkConstructor(TrustedIssuerFlowHandler::class)
        mockkConstructor(IssuerMetadataService::class)

        getProofs = { _ ->
            CredentialRequestProofs(proofs = listOf("mock.jwt.proof"))
        }
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should return issuer metadata result on getIssuerMetadata`() = runBlocking {
        val mockIssuerMetadata = emptyMap<String, String>()
        coEvery {
            anyConstructed<IssuerMetadataService>().fetchAndParseIssuerMetadata(any())
        } returns mockIssuerMetadata

        val issuerMetadataResult = VCIClient("trace-id").getIssuerMetadata(
            credentialIssuer = "https://example.com/issuer"
        )

        assertEquals(mockIssuerMetadata, issuerMetadataResult)
    }

    @Test
    fun `should throw mapped VCIClient exception on getIssuerMetadata`() = runBlocking {
        coEvery {
            anyConstructed<IssuerMetadataService>().fetchAndParseIssuerMetadata(any())
        } throws IssuerMetadataFetchException("Failed to fetch metadata")

        val vciClientException = assertThrows<VCIClientException> {
            runBlocking {
                VCIClient("trace-id").getIssuerMetadata(
                    credentialIssuer = "https://example.com/issuer"
                )
            }
        }

        assertEquals(
            "Failed to fetch issuerMetadata - Failed to fetch metadata",
            vciClientException.message
        )
    }

    @Test
    fun `should throw unknown VCIClient exception on unexpected getIssuerMetadata failure`() {
        coEvery {
            anyConstructed<IssuerMetadataService>().fetchAndParseIssuerMetadata(any())
        } throws RuntimeException("boom")

        val exception = assertThrows<VCIClientException> {
            runBlocking {
                VCIClient("trace-id").getIssuerMetadata(
                    credentialIssuer = "https://example.com/issuer"
                )
            }
        }

        assertEquals("Unknown Exception - boom", exception.message)
    }

    @Test
    fun `should return credential when trusted issuer flow succeeds`() = runBlocking {
        coEvery {
            anyConstructed<TrustedIssuerFlowHandler>().downloadCredentials(any(), any())
        } returns mockCredentialResponse

        val result = VCIClient("trace-id").fetchCredentialsFromTrustedIssuer(
            credentialIssuer = "https://example.com/issuer",
            credentialConfigurationId = "config-id",
            clientMetadata = mockk(),
            getTokenResponse = mockk(relaxed = true),
            authorizations = listOf(mockk<AuthorizationMethod>()),
            getProofs = getProofs,
            downloadTimeoutInMillis = 10000
        )

        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should return credential configurations supported`() = runBlocking {
        val configurations = mapOf("UniversityDegreeCredential" to mapOf("format" to "ldp_vc"))
        coEvery {
            anyConstructed<IssuerMetadataService>().fetchCredentialConfigurationsSupported(any())
        } returns configurations

        val result = VCIClient("trace-id").getCredentialConfigurationsSupported(
            credentialIssuer = "https://example.com/issuer"
        )

        assertEquals(configurations, result)
    }

    @Test
    fun `should throw mapped VCIClient exception on getCredentialConfigurationsSupported`() {
        coEvery {
            anyConstructed<IssuerMetadataService>().fetchCredentialConfigurationsSupported(any())
        } throws IssuerMetadataFetchException("Failed to fetch configurations")

        val exception = assertThrows<VCIClientException> {
            runBlocking {
                VCIClient("trace-id").getCredentialConfigurationsSupported(
                    credentialIssuer = "https://example.com/issuer"
                )
            }
        }

        assertEquals(
            "Failed to fetch issuerMetadata - Failed to fetch configurations",
            exception.message
        )
    }

    @Test
    fun `should throw unknown VCIClient exception on unexpected getCredentialConfigurationsSupported failure`() {
        coEvery {
            anyConstructed<IssuerMetadataService>().fetchCredentialConfigurationsSupported(any())
        } throws RuntimeException("boom")

        val exception = assertThrows<VCIClientException> {
            runBlocking {
                VCIClient("trace-id").getCredentialConfigurationsSupported(
                    credentialIssuer = "https://example.com/issuer"
                )
            }
        }

        assertEquals("Unknown Exception - boom", exception.message)
    }

    @Test
    fun `should return credential when credential offer flow succeeds`() = runBlocking {
        coEvery {
            anyConstructed<CredentialOfferFlowHandler>().downloadCredentials(any(), any(), any())
        } returns mockCredentialResponse

        val result = VCIClient("trace-id").fetchCredentialsUsingCredentialOffer(
            credentialOffer = "sample-offer",
            clientMetadata = ClientMetadata("wallet", "https://sample-app"),
            getTxCode = null,
            authorizations = listOf(mockk<AuthorizationMethod>()),
            getTokenResponse = mockk(relaxed = true),
            getProofs = getProofs,
            onCheckIssuerTrust = null,
            downloadTimeoutInMillis = 10000
        )

        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should throw VCIClientException when trusted issuer flow throws`() {
        coEvery {
            anyConstructed<TrustedIssuerFlowHandler>().downloadCredentials(any(), any())
        } throws Exception("flow error")

        assertThrows<VCIClientException> {
            runBlocking {
                VCIClient("trace-id").fetchCredentialsFromTrustedIssuer(
                    credentialIssuer = "https://example.com/issuer",
                    credentialConfigurationId = "config-id",
                    clientMetadata = mockk(),
                    getTokenResponse = mockk(relaxed = true),
                    authorizations = listOf(mockk<AuthorizationMethod>()),
                    getProofs = getProofs,
                    downloadTimeoutInMillis = 10000
                )
            }
        }
    }

    @Test
    fun `should preserve existing VCIClientException details from trusted issuer flow`() {
        coEvery {
            anyConstructed<TrustedIssuerFlowHandler>().downloadCredentials(any(), any())
        } throws VCIClientException(
            code = "VCI-777",
            message = "trusted issuer failed",
            issuerErrorCode = "invalid_request",
            issuerErrorDescription = "missing proof"
        )

        val exception = assertThrows<VCIClientException> {
            runBlocking {
                VCIClient("trace-id").fetchCredentialsFromTrustedIssuer(
                    credentialIssuer = "https://example.com/issuer",
                    credentialConfigurationId = "config-id",
                    clientMetadata = mockk(),
                    getTokenResponse = mockk(relaxed = true),
                    authorizations = listOf(mockk<AuthorizationMethod>()),
                    getProofs = getProofs
                )
            }
        }

        assertEquals("VCI-777", exception.code)
        assertEquals("invalid_request", exception.issuerErrorCode)
        assertEquals("missing proof", exception.issuerErrorDescription)
    }

    @Test
    fun `should throw VCIClientException when credential offer flow throws`() {
        coEvery {
            anyConstructed<CredentialOfferFlowHandler>().downloadCredentials(any(), any(), any())
        } throws Exception("flow error")

        assertThrows<VCIClientException> {
            runBlocking {
                VCIClient("trace-id").fetchCredentialsUsingCredentialOffer(
                    credentialOffer = "sample-offer",
                    clientMetadata = ClientMetadata("wallet", "https://sample-app"),
                    getTxCode = null,
                    authorizations = listOf(mockk<AuthorizationMethod>()),
                    getTokenResponse = mockk(relaxed = true),
                    getProofs = getProofs,
                    onCheckIssuerTrust = null,
                    downloadTimeoutInMillis = 10000
                )
            }
        }
    }

    @Test
    fun `should preserve existing VCIClientException details from credential offer flow`() {
        coEvery {
            anyConstructed<CredentialOfferFlowHandler>().downloadCredentials(any(), any(), any())
        } throws VCIClientException(
            code = "VCI-778",
            message = "credential offer failed",
            issuerErrorCode = "access_denied",
            issuerErrorDescription = "issuer blocked"
        )

        val exception = assertThrows<VCIClientException> {
            runBlocking {
                VCIClient("trace-id").fetchCredentialsUsingCredentialOffer(
                    credentialOffer = "sample-offer",
                    clientMetadata = ClientMetadata("wallet", "https://sample-app"),
                    getTxCode = null,
                    authorizations = listOf(mockk<AuthorizationMethod>()),
                    getTokenResponse = mockk(relaxed = true),
                    getProofs = getProofs,
                    onCheckIssuerTrust = null
                )
            }
        }

        assertEquals("VCI-778", exception.code)
        assertEquals("access_denied", exception.issuerErrorCode)
        assertEquals("issuer blocked", exception.issuerErrorDescription)
    }

    @Test
    fun `generateTokenDPoPProof throws when there is no active flow`() {
        val exception = assertThrows<VCIClientException> {
            VCIClient("trace-id").generateTokenDPoPProof("nonce")
        }
        assertEquals("VCI-013", exception.code)
    }

    @Test
    fun `generateTokenDPoPProof returns a valid dpop proof when a flow is active`() {
        val client = VCIClient("trace-id")
        val dpopManagerField = VCIClient::class.java.getDeclaredField("dpopManager")
        dpopManagerField.isAccessible = true
        val dpopManager = dpopManagerField.get(client) as io.mosip.vciclient.dpop.DPoPManager
        dpopManager.initialize("https://as.example.com/token", listOf("ES256"))

        val proof = client.generateTokenDPoPProof("test-nonce")

        val jwt = com.nimbusds.jwt.SignedJWT.parse(proof)
        assertEquals("dpop+jwt", jwt.header.type.toString())
        assertEquals("test-nonce", jwt.jwtClaimsSet.getStringClaim("nonce"))
        assertEquals("POST", jwt.jwtClaimsSet.getStringClaim("htm"))
    }
}
