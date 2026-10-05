package io.mosip.vciclient.credentialOffer

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import io.mosip.vciclient.proof.ProofBindingContext
import io.mosip.vciclient.proof.toProofBindingContext
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeCredentialRequest
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationMethod
import io.mosip.vciclient.authorizationCodeFlow.CredentialRequestConfiguration
import io.mosip.vciclient.authorizationCodeFlow.CredentialRequestOptions
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
import io.mosip.vciclient.preAuthCodeFlow.CredentialRequestContext
import io.mosip.vciclient.preAuthCodeFlow.PreAuthCodeFlowService
import io.mosip.vciclient.preAuthCodeFlow.PreAuthFlowOptions

private const val UNSUPPORTED_GRANT_TYPE_ERROR = "Credential offer does not contain a supported grant type"

data class AuthorizationCodeRequestOptions(
    val clientMetadata: ClientMetadata,
    val authorizationMethods: List<AuthorizationMethod>,
    val traceabilityId: String? = null,
)

data class CredentialTransactionOptions(
    val getTxCode: TxCodeCallback?,
    val getTokenResponse: TokenResponseCallback,
    val onCheckIssuerTrust: CheckIssuerTrustCallback? = null,
    val downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    val dpopManager: DPoPManager = DPoPManager(),
)

data class CredentialDownloadRequest(
    val authorizationCodeOptions: AuthorizationCodeRequestOptions,
    val transactionOptions: CredentialTransactionOptions,
)

class CredentialOfferFlowHandler internal constructor(
    private val credentialOfferService: CredentialOfferService = CredentialOfferService(),
    private val issuerMetadataService: IssuerMetadataService = IssuerMetadataService(),
    private val preAuthFlowService: PreAuthCodeFlowService = PreAuthCodeFlowService(),
    private val authorizationCodeFlowService: AuthorizationCodeFlowService = AuthorizationCodeFlowService(),
) {

    suspend fun downloadCredentials(
        credentialOffer: String,
        getProofs: ProofsCallback,
        request: CredentialDownloadRequest,
    ): CredentialResponse {
        val txOpts = request.transactionOptions
        return executeDownloadCredentials(
            credentialOffer = credentialOffer,
            onCheckIssuerTrust = txOpts.onCheckIssuerTrust,
        ) { offer, issuerMetadataResponse, credentialConfigurationId, proofBindingContext ->
            when (issuerMetadataResponse.issuerMetadata.specVersion) {
                OID4VCIVersion.V1 -> {
                    if (offer.isPreAuthorizedFlow()) {
                        preAuthFlowService.requestCredentials(
                            context = CredentialRequestContext(
                                issuerMetadata = issuerMetadataResponse.issuerMetadata,
                                proofBindingContext = proofBindingContext,
                                credentialConfigurationId = credentialConfigurationId,
                            ),
                            options = PreAuthFlowOptions(
                                getTokenResponse = txOpts.getTokenResponse,
                                offer = offer,
                                getTxCode = txOpts.getTxCode,
                                downloadTimeoutInMillis = txOpts.downloadTimeoutInMillis,
                                dpopManager = txOpts.dpopManager,
                            ),
                            getProofs = getProofs,
                        )
                    } else if (offer.isAuthorizationCodeFlow()) {
                        val authOpts = request.authorizationCodeOptions
                        authorizationCodeFlowService.requestCredentials(
                            request = AuthorizationCodeCredentialRequest(
                                configuration = CredentialRequestConfiguration(
                                    issuerMetadata = issuerMetadataResponse.issuerMetadata,
                                    credentialConfigurationId = credentialConfigurationId,
                                    clientMetadata = authOpts.clientMetadata,
                                    authorizationMethods = authOpts.authorizationMethods,
                                ),
                                options = CredentialRequestOptions(
                                    proofBindingContext = proofBindingContext,
                                    credentialOffer = offer,
                                    downloadTimeoutInMillis = txOpts.downloadTimeoutInMillis,
                                    traceabilityId = authOpts.traceabilityId,
                                    dpopManager = txOpts.dpopManager,
                                ),
                                getTokenResponse = txOpts.getTokenResponse,
                            ),
                            getProofs = getProofs,
                        )
                    } else {
                        throw CredentialOfferFetchFailedException(UNSUPPORTED_GRANT_TYPE_ERROR)
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
                            context = CredentialRequestContext(
                                issuerMetadata = issuerMetadataResponse.issuerMetadata,
                                proofBindingContext = proofBindingContext,
                                credentialConfigurationId = credentialConfigurationId,
                            ),
                            options = PreAuthFlowOptions(
                                getTokenResponse = txOpts.getTokenResponse,
                                offer = offer,
                                getTxCode = txOpts.getTxCode,
                                downloadTimeoutInMillis = txOpts.downloadTimeoutInMillis,
                                dpopManager = txOpts.dpopManager,
                            ),
                            getProofJwt = proofJwtCallback,
                        )
                    } else if (offer.isAuthorizationCodeFlow()) {
                        val authOpts = request.authorizationCodeOptions
                        authorizationCodeFlowService.requestCredentialsDraft13(
                            request = AuthorizationCodeCredentialRequest(
                                configuration = CredentialRequestConfiguration(
                                    issuerMetadata = issuerMetadataResponse.issuerMetadata,
                                    credentialConfigurationId = credentialConfigurationId,
                                    clientMetadata = authOpts.clientMetadata,
                                    authorizationMethods = authOpts.authorizationMethods,
                                ),
                                options = CredentialRequestOptions(
                                    proofBindingContext = proofBindingContext,
                                    credentialOffer = offer,
                                    downloadTimeoutInMillis = txOpts.downloadTimeoutInMillis,
                                    traceabilityId = authOpts.traceabilityId,
                                    dpopManager = txOpts.dpopManager,
                                ),
                                getTokenResponse = txOpts.getTokenResponse,
                            ),
                            getProofJwt = proofJwtCallback,
                        )
                    } else {
                        throw CredentialOfferFetchFailedException(UNSUPPORTED_GRANT_TYPE_ERROR)
                    }
                    if (draft13Response.credential.isJsonNull) {
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
    }

    suspend fun downloadCredentialsDraft13(
        credentialOffer: String,
        getProofJwt: ProofJwtCallback,
        request: CredentialDownloadRequest,
    ): CredentialResponseDraft13 {
        val txOpts = request.transactionOptions
        val result = executeDownloadCredentials(
            credentialOffer = credentialOffer,
            onCheckIssuerTrust = txOpts.onCheckIssuerTrust,
        ) { offer, issuerMetadataResponse, credentialConfigurationId, proofBindingContext ->
            if (offer.isPreAuthorizedFlow()) {
                preAuthFlowService.requestCredentialsDraft13(
                    context = CredentialRequestContext(
                        issuerMetadata = issuerMetadataResponse.issuerMetadata,
                        proofBindingContext = proofBindingContext,
                        credentialConfigurationId = credentialConfigurationId,
                    ),
                    options = PreAuthFlowOptions(
                        getTokenResponse = txOpts.getTokenResponse,
                        offer = offer,
                        getTxCode = txOpts.getTxCode,
                        downloadTimeoutInMillis = txOpts.downloadTimeoutInMillis,
                        dpopManager = txOpts.dpopManager,
                    ),
                    getProofJwt = getProofJwt,
                )
            } else if (offer.isAuthorizationCodeFlow()) {
                val authOpts = request.authorizationCodeOptions
                authorizationCodeFlowService.requestCredentialsDraft13(
                    request = AuthorizationCodeCredentialRequest(
                        configuration = CredentialRequestConfiguration(
                            issuerMetadata = issuerMetadataResponse.issuerMetadata,
                            credentialConfigurationId = credentialConfigurationId,
                            clientMetadata = authOpts.clientMetadata,
                            authorizationMethods = authOpts.authorizationMethods,
                        ),
                        options = CredentialRequestOptions(
                            proofBindingContext = proofBindingContext,
                            credentialOffer = offer,
                            downloadTimeoutInMillis = txOpts.downloadTimeoutInMillis,
                            traceabilityId = authOpts.traceabilityId,
                            dpopManager = txOpts.dpopManager,
                        ),
                        getTokenResponse = txOpts.getTokenResponse,
                    ),
                    getProofJwt = getProofJwt,
                )
            } else {
                throw CredentialOfferFetchFailedException(UNSUPPORTED_GRANT_TYPE_ERROR)
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
        executeFlow: suspend (CredentialOffer, IssuerMetadataResult, String, ProofBindingContext) -> Response,
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

        val mapListType = object : TypeToken<List<Map<String, Any>>>() {}.type
        val issuerDisplay: List<Map<String, Any>> = try {
            Gson().fromJson(Gson().toJson(issuerMetadataResponse.raw["display"]), mapListType)
                ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }

        ensureIssuerTrust(
            credentialIssuer = offer.credentialIssuer,
            issuerDisplay = issuerDisplay,
            onCheckIssuerTrust = onCheckIssuerTrust
        )

        return executeFlow(
            offer,
            issuerMetadataResponse,
            credentialConfigurationId,
            issuerMetadataResponse.toProofBindingContext(credentialConfigurationId)
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
