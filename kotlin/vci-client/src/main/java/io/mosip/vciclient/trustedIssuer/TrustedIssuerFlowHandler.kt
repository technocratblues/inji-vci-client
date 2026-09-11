package io.mosip.vciclient.trustedIssuer

import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationMethod
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.constants.OID4VCIVersion
import io.mosip.vciclient.constants.ProofJwtCallback
import io.mosip.vciclient.constants.ProofsCallback
import io.mosip.vciclient.constants.TokenResponseCallback
import io.mosip.vciclient.credential.response.CredentialItem
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.dpop.DPoPManager
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.proof.toProofBindingContext

class TrustedIssuerFlowHandler internal constructor(
    private val authService: AuthorizationCodeFlowService = AuthorizationCodeFlowService(),
    private val issuerMetadataService: IssuerMetadataService = IssuerMetadataService(),
) {
    suspend fun downloadCredentials(
        credentialIssuer: String,
        credentialConfigurationId: String,
        clientMetadata: ClientMetadata,
        getTokenResponse: TokenResponseCallback,
        getProofs: ProofsCallback,
        authorizationMethods: List<AuthorizationMethod>,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        dpopManager: DPoPManager = DPoPManager(),
    ): CredentialResponse {
        val issuerMetadata = loadIssuerMetadata(credentialIssuer, credentialConfigurationId)
        val proofBindingContext = issuerMetadata.toProofBindingContext(credentialConfigurationId)
        val isHolderBindingRequired = issuerMetadata.isHolderBindingRequired(
            credentialConfigurationId
        )

        return when (issuerMetadata.issuerMetadata.specVersion) {
            OID4VCIVersion.V1 -> authService.requestCredentials(
                issuerMetadata = issuerMetadata.issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                clientMetadata = clientMetadata,
                getTokenResponse = getTokenResponse,
                getProofs = getProofs,
                authorizationMethods = authorizationMethods,
                downloadTimeOutInMillis = downloadTimeoutInMillis,
                proofBindingContext = proofBindingContext,
                isHolderBindingRequired = isHolderBindingRequired,
                dpopManager = dpopManager
            )

            OID4VCIVersion.DRAFT13 -> {
                val proofJwtCallback: ProofJwtCallback = { proofRequestMetadata ->
                    val proofs = getProofs(proofRequestMetadata)
                    proofs.firstProof
                        ?: throw DownloadFailedException("Draft13 issuer requires a single JWT proof")
                }
                val draft13Response = authService.requestCredentialsDraft13(
                    issuerMetadata = issuerMetadata.issuerMetadata,
                    credentialConfigurationId = credentialConfigurationId,
                    clientMetadata = clientMetadata,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = proofJwtCallback,
                    authorizationMethods = authorizationMethods,
                    downloadTimeOutInMillis = downloadTimeoutInMillis,
                    proofBindingContext = proofBindingContext,
                    isHolderBindingRequired = isHolderBindingRequired,
                    dpopManager = dpopManager
                )
                CredentialResponse(
                    credentials = listOf(CredentialItem(draft13Response.credential)),
                    credentialConfigurationId = draft13Response.credentialConfigurationId,
                    credentialIssuer = draft13Response.credentialIssuer
                )
            }
        }
    }

    private suspend fun loadIssuerMetadata(
        credentialIssuer: String,
        credentialConfigurationId: String,
    ): IssuerMetadataResult {
        return issuerMetadataService.fetchIssuerMetadataResult(
            credentialIssuer,
            credentialConfigurationId
        )
    }
}
