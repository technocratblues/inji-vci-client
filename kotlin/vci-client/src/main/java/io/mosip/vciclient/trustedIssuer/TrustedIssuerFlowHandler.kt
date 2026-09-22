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

data class TrustedIssuerCredentialRequest(
    val credentialIssuer: String,
    val credentialConfigurationId: String,
    val clientMetadata: ClientMetadata,
    val getTokenResponse: TokenResponseCallback,
    val authorizationMethods: List<AuthorizationMethod>,
    val downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    val dpopManager: DPoPManager = DPoPManager(),
)


class TrustedIssuerFlowHandler internal constructor(
    private val authService: AuthorizationCodeFlowService = AuthorizationCodeFlowService(),
    private val issuerMetadataService: IssuerMetadataService = IssuerMetadataService(),
) {
    suspend fun downloadCredentials(
        request: TrustedIssuerCredentialRequest,
        getProofs: ProofsCallback,
    ): CredentialResponse {
        val issuerMetadata = loadIssuerMetadata(
            credentialIssuer = request.credentialIssuer,
            credentialConfigurationId = request.credentialConfigurationId,
        )
         val proofBindingContext = issuerMetadata.toProofBindingContext(
            request.credentialConfigurationId,
        )

        return when (issuerMetadata.issuerMetadata.specVersion) {
            OID4VCIVersion.V1 -> authService.requestCredentials(
                issuerMetadata = issuerMetadata.issuerMetadata,
                credentialConfigurationId = request.credentialConfigurationId,
                clientMetadata = request.clientMetadata,
                getTokenResponse = request.getTokenResponse,
                getProofs = getProofs,
                authorizationMethods = request.authorizationMethods,
                downloadTimeOutInMillis = request.downloadTimeoutInMillis,
                proofBindingContext = proofBindingContext,
                dpopManager = request.dpopManager
            )

            OID4VCIVersion.DRAFT13 -> {
                val proofJwtCallback: ProofJwtCallback = { proofRequestMetadata ->
                    val proofs = getProofs(proofRequestMetadata)
                    proofs.firstProof
                        ?: throw DownloadFailedException("Draft13 issuer requires a single JWT proof")
                }
                val draft13Response = authService.requestCredentialsDraft13(
                    issuerMetadata = issuerMetadata.issuerMetadata,
                    credentialConfigurationId = request.credentialConfigurationId,
                    clientMetadata = request.clientMetadata,
                    getTokenResponse = request.getTokenResponse,
                    getProofJwt = proofJwtCallback,
                    authorizationMethods = request.authorizationMethods,
                    downloadTimeOutInMillis = request.downloadTimeoutInMillis,
                    proofBindingContext = proofBindingContext,
                    dpopManager = request.dpopManager
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
