package io.mosip.vciclient.credentialOffer

import io.mosip.vciclient.proof.ProofBindingContext
import com.google.gson.JsonNull
import com.google.gson.JsonPrimitive
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationMethod
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.AuthorizeUserCallback
import io.mosip.vciclient.constants.CheckIssuerTrustCallback
import io.mosip.vciclient.constants.ProofJwtCallback
import io.mosip.vciclient.constants.TokenResponseCallback
import io.mosip.vciclient.constants.TxCodeCallback
import io.mosip.vciclient.credential.response.CredentialResponseDraft13
import io.mosip.vciclient.exception.CredentialOfferFetchFailedException
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.preAuthCodeFlow.PreAuthCodeFlowService
import io.mosip.vciclient.token.TokenResponse
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class CredentialOfferFlowHandlerTest {
    private val mockCredentialResponse = CredentialResponseDraft13(
        credential = JsonPrimitive("dummy-credential"),
        credentialConfigurationId = "SampleCredential",
        credentialIssuer = "https://issuer.example.com/issuer"
    )
    private val mockCredentialOffer = mockk<CredentialOffer>(
        relaxed = true
    )
    private val mockIssuerMetadataResult = mockk<IssuerMetadataResult>()
    private val mockClientMetadata = mockk<ClientMetadata>()

    private lateinit var txCode: TxCodeCallback
    private lateinit var getProofJwt: ProofJwtCallback
    private lateinit var authorizeUser: AuthorizeUserCallback

    private lateinit var authorizationMethod: AuthorizationMethod
    private lateinit var getTokenResponse: TokenResponseCallback
    private lateinit var onCheckIssuerTrust: CheckIssuerTrustCallback


    @Before
    fun setup() {
        mockkConstructor(CredentialOfferService::class)
        mockkConstructor(IssuerMetadataService::class)
        mockkConstructor(PreAuthCodeFlowService::class)
        mockkConstructor(AuthorizationCodeFlowService::class)
        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns mockCredentialOffer
        coEvery {
            anyConstructed<IssuerMetadataService>().fetchIssuerMetadataResult(
                any(),
                any()
            )
        } returns mockIssuerMetadataResult
        every { mockIssuerMetadataResult.issuerMetadata } returns mockk(relaxed = true)
        every { mockIssuerMetadataResult.raw } returns mapOf("some" to "metadata")
        every { mockIssuerMetadataResult.extractJwtProofSigningAlgorithms(any()) } returns listOf("ES256")
        every { mockIssuerMetadataResult.extractSupportedProofTypes(any()) } returns listOf("jwt")
        every { mockIssuerMetadataResult.extractCryptographicBindingMethods(any()) } returns emptyList()
        every { mockIssuerMetadataResult.isHolderBindingRequired(any()) } returns true
        txCode = object : TxCodeCallback {
            override suspend fun invoke(
                p1: String?, p2: String?, p3: Int?
            ): String = "mock-auth-code"
        }
        authorizeUser = object : AuthorizeUserCallback {
            override suspend fun invoke(
                authEndpoint: String,
            ): String = "mock-auth-code"
        }

        authorizationMethod = AuthorizationMethod.RedirectToWeb(
            openWebPage = {
                val code = authorizeUser.invoke("dummy-endpoint")
                mapOf(
                    "code" to code,
                )
            }
        )

        getProofJwt = { _ -> "mock.jwt.proof" }
        onCheckIssuerTrust = mockk()
        getTokenResponse = { _ -> TokenResponse("accessToken", "accessToken") }
        coEvery { onCheckIssuerTrust.invoke(any(), any()) } returns true
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `should return credential for pre-authorized flow`() = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthCodeGrant("abc123", null),
                authorizationCodeGrant = null
            )
        )

        coEvery {
            anyConstructed<PreAuthCodeFlowService>().requestCredentialsDraft13(
                any(),
                ProofBindingContext(proofSigningAlgorithmsSupported = listOf("ES256"), proofTypesSupported = listOf("jwt")),
                any(),
                any(),
                any(),
                any(),
                offer = any(),
                dpopManager = any()
            )
        } returns mockCredentialResponse

        mockkConstructor(CredentialOfferService::class)
        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns offer

        val result = CredentialOfferFlowHandler().downloadCredentialsDraft13(
            credentialOffer = "some-offer",
            clientMetadata = mockClientMetadata,
            getTxCode = txCode,
            getTokenResponse = getTokenResponse,
            getProofJwt = getProofJwt,
            authorizationMethods = listOf(authorizationMethod),
            onCheckIssuerTrust = onCheckIssuerTrust,
        )

        assertEquals(mockCredentialResponse, result)
    }

    @Test
    fun `should throw if flow type is not supported`(): Unit = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(null, null)
        )

        mockkConstructor(CredentialOfferService::class)
        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns offer

        assertThrows<CredentialOfferFetchFailedException> {
            CredentialOfferFlowHandler().downloadCredentialsDraft13(
                credentialOffer = "some-offer",
                clientMetadata = mockClientMetadata,
                getTxCode = txCode,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                authorizationMethods = listOf(authorizationMethod),
                onCheckIssuerTrust = onCheckIssuerTrust,
            )
        }
    }

    @Test
    fun `should throw if no credential is returned`(): Unit = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = PreAuthCodeGrant("abc123", null),
                authorizationCodeGrant = null
            )
        )

        coEvery {
            anyConstructed<PreAuthCodeFlowService>().requestCredentialsDraft13(
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                offer = any(),
                dpopManager = any()
            )
        } returns CredentialResponseDraft13(
            credential = JsonNull.INSTANCE,
            credentialConfigurationId = "SampleCredential",
            credentialIssuer = "https://issuer.example.com/issuer"
        )

        mockkConstructor(CredentialOfferService::class)
        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns offer

        assertThrows<CredentialOfferFetchFailedException> {
            CredentialOfferFlowHandler().downloadCredentialsDraft13(
                credentialOffer = "some-offer",
                clientMetadata = mockClientMetadata,
                getTxCode = txCode,
                getTokenResponse = getTokenResponse,
                authorizationMethods = listOf(authorizationMethod),
                getProofJwt = getProofJwt,
                onCheckIssuerTrust = onCheckIssuerTrust,
            )
        }
    }

    @Test
    fun `should throw if user does not give trust consent for untrusted issuer`(): Unit =
        runBlocking {
            val offer = CredentialOffer(
                credentialIssuer = "https://issuer.example.com",
                credentialConfigurationIds = listOf("UniversityDegreeCredential"),
                grants = CredentialOfferGrants(
                    preAuthorizedGrant = PreAuthCodeGrant("abc123", null),
                    authorizationCodeGrant = null
                )
            )

            coEvery { onCheckIssuerTrust.invoke(any(), any()) } returns false

            coEvery {
                anyConstructed<CredentialOfferService>().fetchCredentialOffer(any())
            } returns offer

            assertThrows<CredentialOfferFetchFailedException> {
                CredentialOfferFlowHandler().downloadCredentialsDraft13(
                    credentialOffer = "some-offer",
                    clientMetadata = mockClientMetadata,
                    getTxCode = txCode,
                    getTokenResponse = getTokenResponse,
                    authorizationMethods = listOf(authorizationMethod),
                    getProofJwt = getProofJwt,
                    onCheckIssuerTrust = onCheckIssuerTrust,
                )
            }
        }

    @Test
    fun `should throw batch credential not supported exception when the provided credential offer contains more than one credentialConfigurationIds`() =
        runBlocking {
            val offer = CredentialOffer(
                credentialIssuer = "https://issuer.example.com",
                credentialConfigurationIds = listOf(
                    "UniversityDegreeCredential",
                    "CollegeTranscriptCredential"
                ),
                grants = CredentialOfferGrants(
                    preAuthorizedGrant = PreAuthCodeGrant("abc123", null),
                    authorizationCodeGrant = null
                )
            )
            coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns offer

            val downloadFailedException = assertThrows<DownloadFailedException> {
                CredentialOfferFlowHandler().downloadCredentialsDraft13(
                    credentialOffer = "some-offer",
                    clientMetadata = mockClientMetadata,
                    getTxCode = txCode,
                    getTokenResponse = getTokenResponse,
                    authorizationMethods = listOf(authorizationMethod),
                    getProofJwt = getProofJwt,
                    onCheckIssuerTrust = onCheckIssuerTrust,
                )
            }

            assertEquals(
                "Failed to download Credential: Batch credential request is not supported.",
                downloadFailedException.message
            )
        }

    @Test
    fun `should throw exception for unsupported grant type`() = runBlocking {
        every { mockCredentialOffer.isPreAuthorizedFlow() } returns false
        every { mockCredentialOffer.isAuthorizationCodeFlow() } returns false
        every { mockCredentialOffer.credentialConfigurationIds } returns listOf("config1")
        val grants = CredentialOfferGrants(
            preAuthorizedGrant = null,
            authorizationCodeGrant = null
        )
        every { mockCredentialOffer.grants } returns grants
        val handler = CredentialOfferFlowHandler()
        val ex = assertThrows<CredentialOfferFetchFailedException> {
            runBlocking {
                handler.downloadCredentialsDraft13(
                    credentialOffer = "dummy-offer",
                    clientMetadata = mockClientMetadata,
                    getTxCode = txCode,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    authorizationMethods = listOf(authorizationMethod),
                    onCheckIssuerTrust = onCheckIssuerTrust
                )
            }
        }
        assertEquals(
            "Credential offer does not contain a supported grant type",
            ex.message.substringAfterLast("fetch credential offer: ")
        )
    }

    @Test
    fun `should throw exception for null credential response`() = runBlocking {
        every { mockCredentialOffer.isPreAuthorizedFlow() } returns true
        val grants = CredentialOfferGrants(
            preAuthorizedGrant = PreAuthCodeGrant("abc123", null),
            authorizationCodeGrant = null
        )
        every { mockCredentialOffer.grants } returns grants
        every { mockCredentialOffer.credentialConfigurationIds } returns listOf("config1")
        coEvery {
            anyConstructed<PreAuthCodeFlowService>().requestCredentialsDraft13(
                any(),
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
        } returns CredentialResponseDraft13(
            credential = JsonNull.INSTANCE,
            credentialConfigurationId = "SampleCredential",
            credentialIssuer = "https://issuer.example.com/issuer"
        )
        val handler = CredentialOfferFlowHandler()
        val ex = assertThrows<CredentialOfferFetchFailedException> {
            runBlocking {
                handler.downloadCredentialsDraft13(
                    credentialOffer = "dummy-offer",
                    clientMetadata = mockClientMetadata,
                    getTxCode = txCode,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    authorizationMethods = listOf(authorizationMethod),
                    onCheckIssuerTrust = onCheckIssuerTrust
                )
            }
        }
        assertEquals(
            "No credential response found",
            ex.message.substringAfterLast("fetch credential offer: ")
        )
    }

    @Test
    fun `should throw exception for batch credential request`() = runBlocking {
        every { mockCredentialOffer.credentialConfigurationIds } returns listOf(
            "config1",
            "config2"
        )
        val handler = CredentialOfferFlowHandler()
        val ex = assertThrows<DownloadFailedException> {
            runBlocking {
                handler.downloadCredentialsDraft13(
                    credentialOffer = "dummy-offer",
                    clientMetadata = mockClientMetadata,
                    getTxCode = txCode,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    authorizationMethods = listOf(authorizationMethod),
                    onCheckIssuerTrust = onCheckIssuerTrust
                )
            }
        }
        assertEquals(
            "Failed to download Credential: Batch credential request is not supported.",
            ex.message
        )
    }

    @Test
    fun `should throw exception if issuer not trusted`() = runBlocking {
        every { mockCredentialOffer.isPreAuthorizedFlow() } returns true
        every { mockCredentialOffer.credentialConfigurationIds } returns listOf("config1")
        coEvery { onCheckIssuerTrust.invoke(any(), any()) } returns false
        coEvery {
            anyConstructed<PreAuthCodeFlowService>().requestCredentialsDraft13(
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
        } returns mockCredentialResponse
        val handler = CredentialOfferFlowHandler()
        val ex = assertThrows<CredentialOfferFetchFailedException> {
            runBlocking {
                handler.downloadCredentialsDraft13(
                    credentialOffer = "dummy-offer",
                    clientMetadata = mockClientMetadata,
                    getTxCode = txCode,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    authorizationMethods = listOf(authorizationMethod),
                    onCheckIssuerTrust = onCheckIssuerTrust
                )
            }
        }
        assertEquals(
            "Issuer not trusted by user",
            ex.message.substringAfterLast("fetch credential offer: ")
        )
    }

    @Test
    fun `should request credential via authorization code flow with default issuer display`() = runBlocking {
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentialConfigurationIds = listOf("UniversityDegreeCredential"),
            grants = CredentialOfferGrants(
                preAuthorizedGrant = null,
                authorizationCodeGrant = AuthorizationCodeGrant("issuer-state")
            )
        )
        val issuerMetadataResult = mockk<IssuerMetadataResult>()

        coEvery { anyConstructed<CredentialOfferService>().fetchCredentialOffer(any()) } returns offer
        coEvery {
            anyConstructed<IssuerMetadataService>().fetchIssuerMetadataResult(
                offer.credentialIssuer,
                "UniversityDegreeCredential"
            )
        } returns issuerMetadataResult
        every { issuerMetadataResult.issuerMetadata } returns mockk(relaxed = true)
        every { issuerMetadataResult.raw } returns emptyMap()
        every { issuerMetadataResult.extractJwtProofSigningAlgorithms("UniversityDegreeCredential") } returns listOf("ES256")
        every { issuerMetadataResult.extractSupportedProofTypes("UniversityDegreeCredential") } returns listOf("jwt")
        every { issuerMetadataResult.extractCryptographicBindingMethods("UniversityDegreeCredential") } returns emptyList()
        every { issuerMetadataResult.isHolderBindingRequired("UniversityDegreeCredential") } returns true

        coEvery {
            onCheckIssuerTrust.invoke(
                offer.credentialIssuer,
                listOf(emptyMap())
            )
        } returns true

        coEvery {
            anyConstructed<AuthorizationCodeFlowService>().requestCredentialsDraft13(
                issuerMetadata = issuerMetadataResult.issuerMetadata,
                credentialConfigurationId = "UniversityDegreeCredential",
                clientMetadata = mockClientMetadata,
                getTokenResponse = getTokenResponse,
                getProofJwt = getProofJwt,
                credentialOffer = offer,
                downloadTimeOutInMillis = any(),
                proofBindingContext = ProofBindingContext(proofSigningAlgorithmsSupported = listOf("ES256"), proofTypesSupported = listOf("jwt")),
                authorizationMethods = listOf(authorizationMethod),
                traceabilityId = "trace-id",
                dpopManager = any()
            )
        } returns mockCredentialResponse

        val result = CredentialOfferFlowHandler().downloadCredentialsDraft13(
            credentialOffer = "some-offer",
            clientMetadata = mockClientMetadata,
            getTxCode = txCode,
            getTokenResponse = getTokenResponse,
            getProofJwt = getProofJwt,
            authorizationMethods = listOf(authorizationMethod),
            onCheckIssuerTrust = onCheckIssuerTrust,
            traceabilityId = "trace-id"
        )

        assertEquals(mockCredentialResponse, result)
    }
}
