package io.mosip.vciclient.preAuthCodeFlow

import io.mosip.vciclient.proof.ProofBindingContext
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mockk.verify
import io.mosip.vciclient.authorizationServer.AuthorizationServerResolver
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.credential.request.CredentialRequestExecutor
import io.mosip.vciclient.credential.response.CredentialResponseDraft13
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.credentialOffer.CredentialOfferGrants
import io.mosip.vciclient.credentialOffer.PreAuthCodeGrant
import io.mosip.vciclient.credentialOffer.TxCode
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidDataProvidedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService
import io.mosip.vciclient.constants.ProofJwtCallback
import io.mosip.vciclient.constants.TxCodeCallback
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertTrue

class PreAuthCodeFlowServiceTest {
    private val proofBindingContext = ProofBindingContext(
        proofSigningAlgorithmsSupported = listOf("ES256"),
        cryptographicBindingMethodsSupported = listOf("did:jwk"),
        proofTypesSupported = listOf("jwt"),
    )

    private val mockCredentialResponse = mockk<CredentialResponseDraft13>()
    private val resolvedIssuerMetaData = mockk<IssuerMetadata>()
    private val credentialConfigurationId = "UniversityDegreeCredential"

    private lateinit var getTxCode: TxCodeCallback
    private lateinit var getProofJwt: ProofJwtCallback

    @Before
    fun setup() {
        mockkConstructor(AuthorizationServerResolver::class)
        mockkConstructor(TokenService::class)
        mockkConstructor(CredentialRequestExecutor::class)
        mockkObject(Util.Companion)
        every { Util.getLogTag(any(), any()) } returns "TestLogTag"


        // Add mock for credentialIssuer
        every { resolvedIssuerMetaData.credentialIssuer } returns "https://mock.issuer"

        coEvery {
            anyConstructed<AuthorizationServerResolver>().resolveForPreAuth(any(), any())
        } returns mockk {
            every { tokenEndpoint } returns "https://mock.token.endpoint"
            every { dpopSigningAlgValuesSupported } returns null
        }

        every {
            anyConstructed<CredentialRequestExecutor>().requestCredentialDraft13(
                any(), any(), any(), any(), any(), any(), any()
            )
        } returns mockCredentialResponse

        getTxCode = object : TxCodeCallback {
            override suspend fun invoke(p1: String?, p2: String?, p3: Int?): String = "mockTxCode"
        }

        getProofJwt = { _ -> "mock.jwt.proof" }

        mockkConstructor(io.mosip.vciclient.proof.jwt.JWTProof::class)
        every { anyConstructed<io.mosip.vciclient.proof.jwt.JWTProof>().jwt } returns "mock.jwt"
    }


    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should return credential when token is retrieved successfully`() = runBlocking {
        mockkConstructor(TokenService::class)

        coEvery {
            anyConstructed<TokenService>().getAccessToken(
                getTokenResponse = any(),
                tokenEndpoint = any(),
                preAuthCode = any(),
                txCode = any(),
                dpopManager = any()
            )
        } returns TokenResponse(
            accessToken = "mock-access-token",
            tokenType = "jwt",
            expiresIn = 3600,
            cNonce = "mock-cNonce",
            cNonceExpiresIn = 3600
        )

        val offer = CredentialOffer(
            credentialIssuer = "https://mock.issuer",
            credentialConfigurationIds = listOf(credentialConfigurationId),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthCodeGrant(
                    preAuthCode = "abc123",
                    txCode = TxCode(inputMode = "text")
                )
            )
        )

        val result = PreAuthCodeFlowService().requestCredentialsDraft13(
            issuerMetadata = resolvedIssuerMetaData,
            proofBindingContext = proofBindingContext,
            getTokenResponse = mockk(relaxed = true),
            getProofJwt = getProofJwt,
            credentialConfigurationId = credentialConfigurationId,
            getTxCode = getTxCode,
            downloadTimeoutInMillis = 10000L,
            offer = offer
        )

        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should request credential without proof when holder binding is not required`() = runBlocking {
        coEvery {
            anyConstructed<TokenService>().getAccessToken(
                getTokenResponse = any(),
                tokenEndpoint = any(),
                preAuthCode = any(),
                txCode = any(),
                dpopManager = any()
            )
        } returns TokenResponse(accessToken = "mock-access-token", tokenType = "Bearer")

        val offer = CredentialOffer(
            credentialIssuer = "https://mock.issuer",
            credentialConfigurationIds = listOf(credentialConfigurationId),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthCodeGrant(preAuthCode = "abc123")
            )
        )

        val result = PreAuthCodeFlowService().requestCredentialsDraft13(
            issuerMetadata = resolvedIssuerMetaData,
            proofBindingContext = ProofBindingContext(proofSigningAlgorithmsSupported = listOf("ES256")),
            getTokenResponse = mockk(relaxed = true),
            getProofJwt = { error("proof JWT callback should not be invoked") },
            credentialConfigurationId = credentialConfigurationId,
            offer = offer
        )

        assertEquals(mockCredentialResponse, result)
        verify {
            anyConstructed<CredentialRequestExecutor>().requestCredentialDraft13(
                issuerMetadata = any(),
                credentialConfigurationId = any(),
                proof = isNull(),
                accessToken = "mock-access-token",
                downloadTimeoutInMillis = any(),
                tokenType = any(),
                dpopManager = any()
            )
        }
    }

    @Test
    fun `should throw DownloadFailedException if tx_code is required but provider is null`() =
        runBlocking {
            val offer = CredentialOffer(
                credentialIssuer = "https://mock.issuer",
                credentialConfigurationIds = listOf(credentialConfigurationId),
                grants = CredentialOfferGrants(
                    preAuthorizedGrant = PreAuthCodeGrant(
                        preAuthCode = "abc123",
                        txCode = TxCode(inputMode = "text")
                    )
                )
            )

            val exception = assertThrows<DownloadFailedException> {
                PreAuthCodeFlowService().requestCredentialsDraft13(
                    issuerMetadata = resolvedIssuerMetaData,
                    proofBindingContext = proofBindingContext,
                    getTokenResponse = mockk(relaxed = true),
                    getProofJwt = getProofJwt,
                    credentialConfigurationId = credentialConfigurationId,
                    getTxCode = null,
                    downloadTimeoutInMillis = 10000L,
                    offer = offer
                )
            }

            assertTrue { exception.message.contains("Failed to download Credential: tx_code required but no provider was given.")}
        }

    @Test
    fun `should throw error when token endpoint is missing`() = runBlocking {
        coEvery {
            anyConstructed<AuthorizationServerResolver>().resolveForPreAuth(any(), any())
        } returns mockk {
            every { tokenEndpoint } returns null
            every { dpopSigningAlgValuesSupported } returns null
        }
        val offer = CredentialOffer(
            credentialIssuer = "https://mock.issuer",
            credentialConfigurationIds = listOf(credentialConfigurationId),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = null,
            )
        )

        val exception = assertThrows<DownloadFailedException> {
            PreAuthCodeFlowService().requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetaData,
                proofBindingContext = proofBindingContext,
                getTokenResponse =  mockk(relaxed = true),
                getProofJwt = getProofJwt,
                credentialConfigurationId = credentialConfigurationId,
                getTxCode = getTxCode,
                downloadTimeoutInMillis = 10000L,
                offer = offer
            )
        }

    }

    @Test
    fun `should throw error when pre-authorized grant details are missing`() {
        val offer = CredentialOffer(
            credentialIssuer = "https://mock.issuer",
            credentialConfigurationIds = listOf(credentialConfigurationId),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = null
            )
        )

        val exception = assertThrows<DownloadFailedException> {
            runBlocking {
                PreAuthCodeFlowService().requestCredentialsDraft13(
                    issuerMetadata = resolvedIssuerMetaData,
                    proofBindingContext = proofBindingContext,
                    getTokenResponse = mockk(relaxed = true),
                    getProofJwt = getProofJwt,
                    credentialConfigurationId = credentialConfigurationId,
                    getTxCode = getTxCode,
                    downloadTimeoutInMillis = 10000L,
                    offer = offer
                )
            }
        }

        assertEquals("Failed to download Credential: Pre-Authorized Code Flow failed: Required details not provided Missing pre-authorized grant details.", exception.message)
    }

    @Test
    fun `should wrap token network error with cause`() = runBlocking {
        val networkException = java.io.IOException("Token network failure")

        mockkConstructor(TokenService::class)
        coEvery {
            anyConstructed<TokenService>().getAccessToken(
                getTokenResponse = any(),
                tokenEndpoint = any(),
                preAuthCode = any(),
                txCode = any(),
                dpopManager = any()
            )
        } throws networkException

        val offer = CredentialOffer(
            credentialIssuer = "https://mock.issuer",
            credentialConfigurationIds = listOf(credentialConfigurationId),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthCodeGrant(
                    preAuthCode = "abc123",
                    txCode = null
                )
            )
        )

        val ex = assertThrows<DownloadFailedException> {
            PreAuthCodeFlowService().requestCredentialsDraft13(
                issuerMetadata = resolvedIssuerMetaData,
                proofBindingContext = proofBindingContext,
                getTokenResponse = mockk(relaxed = true),
                getProofJwt = getProofJwt,
                credentialConfigurationId = credentialConfigurationId,
                getTxCode = getTxCode,
                downloadTimeoutInMillis = 10000L,
                offer = offer
            )
        }

        assertEquals(networkException, ex.cause)
        assert(ex.message.contains("Pre-Authorized Code"))
        assert(ex.message.contains("Token network failure"))
    }
}
