package io.mosip.vciclient.credentialOffer

import io.mosip.vciclient.proof.ProofBindingContext
import io.mosip.vciclient.proof.toProofBindingContext
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationMethod
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.CheckIssuerTrustCallback
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.constants.OID4VCIVersion
import io.mosip.vciclient.constants.ProofJwtCallback
import io.mosip.vciclient.constants.ProofsCallback
import io.mosip.vciclient.constants.TokenResponseCallback
import io.mosip.vciclient.constants.TxCodeCallback
import io.mosip.vciclient.credential.response.CredentialItem
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.credential.response.CredentialResponseDraft13
import io.mosip.vciclient.dpop.DPoPManager
import io.mosip.vciclient.exception.CredentialOfferFetchFailedException
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.preAuthCodeFlow.PreAuthCodeFlowService

class CredentialOfferFlowHandler internal constructor(
    private val credentialOfferService: CredentialOfferService = CredentialOfferService(),
    private val issuerMetadataService: IssuerMetadataService = IssuerMetadataService(),
    private val preAuthFlowService: PreAuthCodeFlowService = PreAuthCodeFlowService(),
    private val authorizationCodeFlowService: AuthorizationCodeFlowService = AuthorizationCodeFlowService(),
) {
    suspend fun downloadCredentials(
        credentialOffer: String,
        clientMetadata: ClientMetadata,
        getTxCode: TxCodeCallback?,
        getTokenResponse: TokenResponseCallback,
        getProofs: ProofsCallback,
        authorizationMethods: List<AuthorizationMethod>,
        onCheckIssuerTrust: CheckIssuerTrustCallback? = null,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        traceabilityId: String? = null,
        dpopManager: DPoPManager = DPoPManager(),
    ): CredentialResponse {
        val result = executeDownloadCredentials(
            credentialOffer = credentialOffer,
            onCheckIssuerTrust = onCheckIssuerTrust,
        ) { offer, issuerMetadataResponse, credentialConfigurationId, proofBindingContext, isHolderBindingRequired ->
            when (issuerMetadataResponse.issuerMetadata.specVersion) {
                OID4VCIVersion.V1 -> {
                    if (offer.isPreAuthorizedFlow()) {
                        preAuthFlowService.requestCredentials(
                            issuerMetadata = issuerMetadataResponse.issuerMetadata,
                            proofBindingContext = proofBindingContext,
                            getTokenResponse = getTokenResponse,
                            getProofs = getProofs,
                            credentialConfigurationId = credentialConfigurationId,
                            getTxCode = getTxCode,
                            downloadTimeoutInMillis = downloadTimeoutInMillis,
                            offer = offer,
                            dpopManager = dpopManager,
                                    isHolderBindingRequired = isHolderBindingRequired
                        )
                    } else if (offer.isAuthorizationCodeFlow()) {
                        authorizationCodeFlowService.requestCredentials(
                            issuerMetadata = issuerMetadataResponse.issuerMetadata,
                            credentialConfigurationId = credentialConfigurationId,
                            clientMetadata = clientMetadata,
                            getTokenResponse = getTokenResponse,
                            getProofs = getProofs,
                            authorizationMethods = authorizationMethods,
                            credentialOffer = offer,
                            downloadTimeOutInMillis = downloadTimeoutInMillis,
                            proofBindingContext = proofBindingContext,
                            traceabilityId = traceabilityId,
                            isHolderBindingRequired = isHolderBindingRequired,
                            dpopManager = dpopManager
                        )
                    } else {
                        throw CredentialOfferFetchFailedException("Credential offer does not contain a supported grant type")
                    }
                }

                OID4VCIVersion.DRAFT13 -> {
                    val proofJwtCallback: ProofJwtCallback = { proofRequestMetadata ->
                        val proofs = getProofs(proofRequestMetadata)
                        proofs.firstProof
                            ?: throw DownloadFailedException("Draft13 issuer requires a single JWT proof")
                    }

                    val draft13Response = if (offer.isPreAuthorizedFlow()) {
                        preAuthFlowService.requestCredentialsDraft13(
                            issuerMetadata = issuerMetadataResponse.issuerMetadata,
                            proofBindingContext = proofBindingContext,
                            getTokenResponse = getTokenResponse,
                            getProofJwt = proofJwtCallback,
                            credentialConfigurationId = credentialConfigurationId,
                            getTxCode = getTxCode,
                            downloadTimeoutInMillis = downloadTimeoutInMillis,
                            offer = offer,
                            dpopManager = dpopManager,
                                    isHolderBindingRequired = isHolderBindingRequired
                        )
                    } else if (offer.isAuthorizationCodeFlow()) {
                        authorizationCodeFlowService.requestCredentialsDraft13(
                            issuerMetadata = issuerMetadataResponse.issuerMetadata,
                            credentialConfigurationId = credentialConfigurationId,
                            clientMetadata = clientMetadata,
                            getTokenResponse = getTokenResponse,
                            getProofJwt = proofJwtCallback,
                            authorizationMethods = authorizationMethods,
                            credentialOffer = offer,
                            downloadTimeOutInMillis = downloadTimeoutInMillis,
                            proofBindingContext = proofBindingContext,
                            traceabilityId = traceabilityId,
                            isHolderBindingRequired = isHolderBindingRequired,
                            dpopManager = dpopManager
                        )
                    } else {
                        throw CredentialOfferFetchFailedException("Credential offer does not contain a supported grant type")
                    }
                    if(draft13Response.credential.isJsonNull)
                    {
                        throw CredentialOfferFetchFailedException("No credential response found")
                    }
                    CredentialResponse(
                        credentials = listOf(CredentialItem(draft13Response.credential)),
                        credentialConfigurationId = draft13Response.credentialConfigurationId,
                        credentialIssuer = draft13Response.credentialIssuer
                    )
                }
            }
        }
        return result
    }

    suspend fun downloadCredentialsDraft13(
        credentialOffer: String,
        clientMetadata: ClientMetadata,
        getTxCode: TxCodeCallback?,
        getTokenResponse: TokenResponseCallback,
        getProofJwt: ProofJwtCallback,
        authorizationMethods: List<AuthorizationMethod>,
        onCheckIssuerTrust: CheckIssuerTrustCallback? = null,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        traceabilityId: String? = null,
    ): CredentialResponseDraft13 {
        val result = executeDownloadCredentials(
            credentialOffer = credentialOffer,
            onCheckIssuerTrust = onCheckIssuerTrust,
        ) { offer, issuerMetadataResponse, credentialConfigurationId, proofBindingContext, isHolderBindingRequired ->
            if (offer.isPreAuthorizedFlow()) {
                preAuthFlowService.requestCredentialsDraft13(
                    issuerMetadata = issuerMetadataResponse.issuerMetadata,
                    proofBindingContext = proofBindingContext,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    credentialConfigurationId = credentialConfigurationId,
                    getTxCode = getTxCode,
                    downloadTimeoutInMillis = downloadTimeoutInMillis,
                    offer = offer,
                            isHolderBindingRequired = isHolderBindingRequired
                )
            } else if (offer.isAuthorizationCodeFlow()) {
                authorizationCodeFlowService.requestCredentialsDraft13(
                    issuerMetadata = issuerMetadataResponse.issuerMetadata,
                    credentialConfigurationId = credentialConfigurationId,
                    clientMetadata = clientMetadata,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    authorizationMethods = authorizationMethods,
                    credentialOffer = offer,
                    downloadTimeOutInMillis = downloadTimeoutInMillis,
                    proofBindingContext = proofBindingContext,
                    traceabilityId = traceabilityId,
                            isHolderBindingRequired = isHolderBindingRequired
                )
            } else {
                throw CredentialOfferFetchFailedException("Credential offer does not contain a supported grant type")
            }
        }
        if (result.credential.isJsonNull) {
            throw CredentialOfferFetchFailedException("No credential response found")
        }
        return result
    }

    private suspend fun <Response> executeDownloadCredentials(
        credentialOffer: String,
        onCheckIssuerTrust: CheckIssuerTrustCallback?,
        executeFlow: suspend (CredentialOffer, IssuerMetadataResult, String, ProofBindingContext, Boolean) -> Response,
    ): Response {
        val offer = credentialOfferService.fetchCredentialOffer(credentialOffer)
        if (offer.credentialConfigurationIds.size > 1) {
            throw DownloadFailedException("Batch credential request is not supported.")
        }

        val credentialConfigurationId = offer.credentialConfigurationIds.firstOrNull()
            ?: throw CredentialOfferFetchFailedException("Credential offer does not contain any credential configuration IDs")
        val issuerMetadataResponse = issuerMetadataService.fetchIssuerMetadataResult(
            offer.credentialIssuer,
            credentialConfigurationId
        )
        val issuerDisplay =
            issuerMetadataResponse.raw["display"] as? List<Map<String, Any>> ?: listOf(emptyMap())

        ensureIssuerTrust(
            credentialIssuer = offer.credentialIssuer,
            issuerDisplay = issuerDisplay,
            onCheckIssuerTrust = onCheckIssuerTrust
        )

        return executeFlow(
            offer,
            issuerMetadataResponse,
            credentialConfigurationId,
            issuerMetadataResponse.toProofBindingContext(credentialConfigurationId),
            issuerMetadataResponse.isHolderBindingRequired(credentialConfigurationId)
        )
    }

    private suspend fun ensureIssuerTrust(
        credentialIssuer: String,
        issuerDisplay: List<Map<String, Any>>,
        onCheckIssuerTrust: CheckIssuerTrustCallback?,
    ) {
        if (onCheckIssuerTrust != null) {
            val consented = onCheckIssuerTrust(credentialIssuer, issuerDisplay)
            if (!consented) {
                throw CredentialOfferFetchFailedException("Issuer not trusted by user")
            }
        }
    }
}
