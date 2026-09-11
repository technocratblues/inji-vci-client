package io.mosip.vciclient.preAuthCodeFlow

import io.mosip.vciclient.proof.ProofBindingContext
import io.mosip.vciclient.authorizationServer.AuthorizationServerResolver
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.constants.ProofJwtCallback
import io.mosip.vciclient.constants.ProofsCallback
import io.mosip.vciclient.constants.TokenResponseCallback
import io.mosip.vciclient.constants.TxCodeCallback
import io.mosip.vciclient.credential.request.CredentialRequestExecutor
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.credential.response.CredentialResponseDraft13
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.dpop.DPoPManager
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidDataProvidedException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.nonce.NonceService
import io.mosip.vciclient.proof.jwt.JWTProof
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService

internal class PreAuthCodeFlowService(
    private val authServerResolver: AuthorizationServerResolver = AuthorizationServerResolver(),
    private val tokenService: TokenService = TokenService(),
    private val credentialExecutor: CredentialRequestExecutor = CredentialRequestExecutor(),
    private val nonceService: NonceService = NonceService(),
) {
    suspend fun requestCredentials(
        issuerMetadata: IssuerMetadata,
        proofBindingContext: ProofBindingContext,
        getTokenResponse: TokenResponseCallback,
        getProofs: ProofsCallback,
        credentialConfigurationId: String,
        getTxCode: TxCodeCallback? = null,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        offer: CredentialOffer,
        isHolderBindingRequired: Boolean = true,
        dpopManager: DPoPManager = DPoPManager(),
    ): CredentialResponse {
        return executeRequestCredentials(
            issuerMetadata = issuerMetadata,
            getTokenResponse = getTokenResponse,
            getTxCode = getTxCode,
            downloadTimeoutInMillis = downloadTimeoutInMillis,
            offer = offer,
            dpopManager = dpopManager
        ) { token ->
            val proofs = if (isHolderBindingRequired) {
            val nonce = resolveNonce(issuerMetadata, downloadTimeoutInMillis, dpopManager)
            try {
                getProofs(
                    proofBindingContext.toCredentialRequestProofMetadata(issuerMetadata.credentialIssuer, nonce)
                )
            } catch (e: Exception) {
                throw DownloadFailedException(
                    "Failed to obtain proofs from callback: ${e.message}",
                    cause = e
                )
            }
            } else {
                null
            }

            credentialExecutor.requestCredential(
                issuerMetadata = issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                proofs = proofs,
                accessToken = token.accessToken,
                downloadTimeoutInMillis = downloadTimeoutInMillis,
                tokenType = token.tokenType,
                dpopManager = dpopManager
            )
        }
    }

    suspend fun requestCredentialsDraft13(
        issuerMetadata: IssuerMetadata,
        proofBindingContext: ProofBindingContext,
        getTokenResponse: TokenResponseCallback,
        getProofJwt: ProofJwtCallback,
        credentialConfigurationId: String,
        getTxCode: TxCodeCallback? = null,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        offer: CredentialOffer,
        isHolderBindingRequired: Boolean = true,
        dpopManager: DPoPManager = DPoPManager(),
    ): CredentialResponseDraft13 {
        return executeRequestCredentials(
            issuerMetadata = issuerMetadata,
            getTokenResponse = getTokenResponse,
            getTxCode = getTxCode,
            downloadTimeoutInMillis = downloadTimeoutInMillis,
            offer = offer,
            dpopManager = dpopManager
        ) { token ->
            val proof = if (isHolderBindingRequired) {
            val nonce = NonceService.extractNonceFromTokenResponse(token)
            val jwt = try {
                getProofJwt(
                    proofBindingContext.toCredentialRequestProofMetadata(issuerMetadata.credentialIssuer, nonce)
                )
            } catch (e: Exception) {
                throw DownloadFailedException(
                    "Failed to obtain proof JWT from callback: ${e.message}",
                    cause = e
                )
            }
                JWTProof(jwt)
            } else {
                null
            }

            credentialExecutor.requestCredentialDraft13(
                issuerMetadata = issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                proof = proof,
                accessToken = token.accessToken,
                downloadTimeoutInMillis = downloadTimeoutInMillis,
                tokenType = token.tokenType,
                dpopManager = dpopManager
            )
        }
    }

    private suspend fun <Response> executeRequestCredentials(
        issuerMetadata: IssuerMetadata,
        getTokenResponse: TokenResponseCallback,
        getTxCode: TxCodeCallback?,
        downloadTimeoutInMillis: Long,
        offer: CredentialOffer,
        dpopManager: DPoPManager,
        requestCredential: suspend (TokenResponse) -> Response?,
    ): Response {
        try {
            val authorizationServerMetadata = authServerResolver.resolveForPreAuth(
                issuerMetadata = issuerMetadata,
                credentialOffer = offer
            )

            val tokenEndpoint = authorizationServerMetadata.tokenEndpoint
                ?: throw DownloadFailedException("Token endpoint is missing in Authorization Server metadata.")

            dpopManager.initialize(
                tokenEndpoint,
                authorizationServerMetadata.dpopSigningAlgValuesSupported
            )

            val grant = offer.grants?.preAuthorizedGrant
                ?: throw InvalidDataProvidedException("Missing pre-authorized grant details.")

            val txCode: String? = if (offer.grants.preAuthorizedGrant.txCode != null) {
                val txCodeInfo = offer.grants.preAuthorizedGrant.txCode
                getTxCode?.invoke(txCodeInfo.inputMode, txCodeInfo.description, txCodeInfo.length)
            } else {
                null
            }

            if (offer.grants.preAuthorizedGrant.txCode != null && txCode == null) {
                throw DownloadFailedException("tx_code required but no provider was given.")
            }

            val token = tokenService.getAccessToken(
                getTokenResponse = getTokenResponse,
                tokenEndpoint = tokenEndpoint,
                preAuthCode = grant.preAuthCode,
                txCode = txCode,
                dpopManager = dpopManager
            )

            return requestCredential(token)
                ?: throw DownloadFailedException("Credential request failed.")
        } catch (e: DownloadFailedException) {
            throw e
        } catch (e: VCIClientException) {
            throw DownloadFailedException(
                "Pre-Authorized Code Flow failed: ${e.message}",
                e.issuerErrorCode,
                e.issuerErrorDescription,
                e
            )
        } catch (e: Exception) {
            throw DownloadFailedException(
                "Unexpected error during Pre-Authorized Code Flow: ${e.message}",
                cause = e
            )
        }
    }

    private suspend fun resolveNonce(
        issuerMetadata: IssuerMetadata,
        timeoutInMillis: Long,
        dpopManager: DPoPManager,
    ): String? {
        return nonceService.fetchNonce(issuerMetadata, timeoutInMillis, dpopManager)
    }
}
