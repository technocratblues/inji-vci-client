package io.mosip.vciclient.authorizationCodeFlow

import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.authorizationCodeFlow.implicitAuthorization.ImplicitAuthorizationRequestData
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.InteractiveAuthorizationHandler
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.redirectToWeb.RedirectToWebAuthorizationMethodService
import io.mosip.vciclient.authorizationServer.AuthorizationServerMetadata
import io.mosip.vciclient.authorizationServer.AuthorizationServerResolver
import io.mosip.vciclient.constants.AuthorizeUserCallback
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.constants.Constants.MISSING_INTERACTION_TYPE_ERROR
import io.mosip.vciclient.constants.ProofJwtCallback
import io.mosip.vciclient.constants.ProofsCallback
import io.mosip.vciclient.constants.TokenResponseCallback
import io.mosip.vciclient.credential.request.CredentialRequestExecutor
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.credential.response.CredentialResponseDraft13
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.dpop.DPoPManager
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.nonce.NonceService
import io.mosip.vciclient.pkce.PKCESessionManager
import io.mosip.vciclient.proof.ProofBindingContext
import io.mosip.vciclient.proof.jwt.JWTProof
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService
import java.util.logging.Logger

internal data class CredentialRequestConfiguration(
    val issuerMetadata: IssuerMetadata,
    val credentialConfigurationId: String,
    val clientMetadata: ClientMetadata,
    val authorizationMethods: List<AuthorizationMethod>,
)

internal data class CredentialRequestOptions(
    val proofBindingContext: ProofBindingContext,
    val credentialOffer: CredentialOffer? = null,
    val downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    val traceabilityId: String? = null,
    val dpopManager: DPoPManager = DPoPManager(),
)

internal data class AuthorizationCodeCredentialRequest(
    val configuration: CredentialRequestConfiguration,
    val options: CredentialRequestOptions,
    val getTokenResponse: TokenResponseCallback,
)

internal class AuthorizationCodeFlowService(
    private val authorizationServerResolver: AuthorizationServerResolver = AuthorizationServerResolver(),
    private val tokenService: TokenService = TokenService(),
    private val credentialExecutor: CredentialRequestExecutor = CredentialRequestExecutor(),
    private val pkceSessionManager: PKCESessionManager = PKCESessionManager(),
    private val interactiveAuthorizationHandler: InteractiveAuthorizationHandler = InteractiveAuthorizationHandler(),
    private val nonceService: NonceService = NonceService(),
) {
    private val logger: Logger = Logger.getLogger(javaClass.simpleName)

 suspend fun requestCredentials(
        request: AuthorizationCodeCredentialRequest,
        getProofs: ProofsCallback,
    ): CredentialResponse {
        return executeRequestCredentials(request) { token ->
            val configuration = request.configuration
            val options = request.options

            val nonce = resolveNonce(
                issuerMetadata = configuration.issuerMetadata,
                timeoutInMillis = options.downloadTimeoutInMillis,
                dpopManager = options.dpopManager,
            )

            val proofs = try {
                getProofs(
                    options.proofBindingContext.toCredentialRequestProofMetadata(
                        configuration.issuerMetadata.credentialIssuer,
                        nonce,
                    ),
                )
            } catch (e: Exception) {
                throw DownloadFailedException(
                    "Failed to obtain proofs from callback: ${e.message}",
                    cause = e,
                )
            }


            credentialExecutor.requestCredential(
                issuerMetadata = issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                proofs = proofs,
                accessToken = token.accessToken,
                downloadTimeoutInMillis = downloadTimeOutInMillis,
                tokenType = token.tokenType,
                dpopManager = dpopManager
            )
        }
    }

    suspend fun requestCredentialsDraft13(
        request: AuthorizationCodeCredentialRequest,
        getProofJwt: ProofJwtCallback,
    ): CredentialResponseDraft13 {
        return executeRequestCredentials(request) { token ->
            val configuration = request.configuration
            val options = request.options
            val nonce = NonceService.extractNonceFromTokenResponse(token)

            val jwt = try {
                getProofJwt(
                    options.proofBindingContext.toCredentialRequestProofMetadata(
                        configuration.issuerMetadata.credentialIssuer,
                        nonce,
                    ),
                )
            } catch (e: Exception) {
                throw DownloadFailedException(
                    "Failed to obtain proof JWT from callback: ${e.message}",
                    cause = e,
                )
            }

            credentialExecutor.requestCredentialDraft13(
                issuerMetadata = issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                proof = JWTProof(jwt),
                accessToken = token.accessToken,
                downloadTimeoutInMillis = downloadTimeOutInMillis,
                tokenType = token.tokenType,
                dpopManager = dpopManager
            )
        }
    }
 private suspend fun <Response> executeRequestCredentials(
        request: AuthorizationCodeCredentialRequest,
        requestCredential: suspend (TokenResponse) -> Response?,
    ): Response {
        val configuration = request.configuration
        val options = request.options

        try {
            val pkceSession = pkceSessionManager.createSession()

            val authorizationServerMetadata = try {
                authorizationServerResolver.resolveForAuthCode(
                    configuration.issuerMetadata,
                    options.credentialOffer,
                )
            } catch (e: DownloadFailedException) {
                throw e
            } catch (e: VCIClientException) {
                throw DownloadFailedException(
                    "Failed to resolve authorization server metadata for issuer " +
                        "${configuration.issuerMetadata.credentialIssuer}: ${e.message}",
                    issuerErrorCode = e.issuerErrorCode,
                    issuerErrorDescription = e.issuerErrorDescription,
                    cause = e,
                )
            } catch (e: Exception) {
                throw DownloadFailedException(
                    "Failed to resolve authorization server metadata for issuer " +
                        "${configuration.issuerMetadata.credentialIssuer}: ${e.message}",
                    cause = e,
                )
            }
            val token = try {
                performAuthorizationAndGetToken(
                    authorizationServerMetadata = authorizationServerMetadata,
                    request = request,
                    pkceSession = pkceSession,
                    
                )
            } catch (e: DownloadFailedException) {
                throw e
            } catch (e: VCIClientException) {
                throw DownloadFailedException(
                    "Failed to obtain access token via authorization code flow: ${e.message}",
                    issuerErrorCode = e.issuerErrorCode,
                    issuerErrorDescription = e.issuerErrorDescription,
                    cause = e
                )
            } catch (e: Exception) {
                throw DownloadFailedException(
                    "Failed to obtain access token via authorization code flow: ${e.message}",
                    cause = e
                )
            }

            return requestCredential(token)
                ?: throw DownloadFailedException("Credential request returned null.")
        } catch (e: DownloadFailedException) {
            throw e
        } catch (e: VCIClientException) {
            throw DownloadFailedException(
                e.message,
                issuerErrorCode = e.issuerErrorCode,
                issuerErrorDescription = e.issuerErrorDescription,
                cause = e
            )
        } catch (e: Exception) {
            throw DownloadFailedException(
                "Download failed via authorization code flow: ${e.message}"
                cause = e,
            )
        }
    }

    private suspend fun performAuthorizationAndGetToken(
        authorizationServerMetadata: AuthorizationServerMetadata,
        request: AuthorizationCodeCredentialRequest,
        pkceSession: PKCESessionManager.PKCESession,,
    ): TokenResponse {
        val tokenEndpoint = configuration.issuerMetadata.tokenEndpoint
            ?: authorizationServerMetadata.tokenEndpoint
            ?: throw DownloadFailedException(
                "Missing token endpoint for issuer ${configuration.issuerMetadata.credentialIssuer}"
            )

        options.dpopManager.initialize(
            tokenEndpoint,
            authorizationServerMetadata.dpopSigningAlgValuesSupported
        )

        val authCode = obtainAuthorizationCode(
            authorizationServerMetadata = authorizationServerMetadata,
            request = request,
            pkceSession = pkceSession,
        )

        return try {
            tokenService.getAccessToken(
                getTokenResponse = getTokenResponse,
                tokenEndpoint = tokenEndpoint,
                authCode = authCode,
                clientId = clientMetadata.clientId,
                redirectUri = clientMetadata.redirectUri,
                codeVerifier = pkceSession.codeVerifier,
                dpopManager = dpopManager
            )
        } catch (e: Exception) {
            throw DownloadFailedException(
                "Failed to exchange authorization code for access token at $tokenEndpoint: ${e.message}",
                cause = e,
            )
        }
    }

    internal fun normalizeAuthorizationMethods(
        authorizeUser: AuthorizeUserCallback?,
        authorizationMethods: List<AuthorizationMethod> = emptyList(),
    ): List<AuthorizationMethod> {
        if (authorizeUser == null) return authorizationMethods

        val redirectToWeb = AuthorizationMethod.RedirectToWeb(
            openWebPage = { authUrl ->
                val code = authorizeUser.invoke(authUrl)
                mapOf("code" to code)
            }
        )

        return authorizationMethods + redirectToWeb
    }

    private suspend fun obtainAuthorizationCode(
        authorizationServerMetadata: AuthorizationServerMetadata,
        request: AuthorizationCodeCredentialRequest
        pkceSession: PKCESessionManager.PKCESession,
    ): String {
        val interactiveEndpoint =
            authorizationServerMetadata.interactiveAuthorizationEndpoint?.trim()

        if (
            authorizationServerMetadata.requireInteractiveAuthorizationRequest == true &&
            interactiveEndpoint.isNullOrEmpty()
        ) {
            throw DownloadFailedException("Missing interactive authorization endpoint")
        }

        return if (!interactiveEndpoint.isNullOrEmpty()) {
            try {
                obtainAuthorizationCodeViaInteractiveAuthorizationEndpoint(
                    endpoint = interactiveEndpoint,
                    request = request,
                    pkceSession = pkceSession,
                )
            } catch (e: DownloadFailedException) {
                if (
                    e.issuerErrorCode == MISSING_INTERACTION_TYPE_ERROR &&
                    authorizationServerMetadata.requireInteractiveAuthorizationRequest != true
                ) {
                    logger.warning(
                        "Interactive authorization failed at $interactiveEndpoint: ${e.message}. Falling back to standard authorization endpoint if available."
                    )

                    obtainAuthorizationCodeViaAuthorizationEndpoint(
                        authorizationServerMetadata = authorizationServerMetadata,
                        request = request,
                        pkceSession = pkceSession,
                    )
                } else {
                    throw e
                }
            }
        } else {
            obtainAuthorizationCodeViaAuthorizationEndpoint(
                authorizationServerMetadata = authorizationServerMetadata,
                request = request,
                pkceSession = pkceSession,
            )
        }
    }
private suspend fun obtainAuthorizationCodeViaInteractiveAuthorizationEndpoint(
    endpoint: String,
    request: AuthorizationCodeCredentialRequest,
    pkceSession: PKCESessionManager.PKCESession,
): String {
     val configuration = request.configuration
        val options = request.options

        val response = try {
            interactiveAuthorizationHandler.handle(
                endpoint = endpoint,
                clientMetadata = clientMetadata,
                credentialConfigurationId = credentialConfigurationId,
                authorizationMethods = authorizationMethods,
                pkceSession = pkceSession,
                traceabilityId = traceabilityId,
                dpopJkt = dpopManager.jwkThumbprint()
            )
        } catch (e: VCIClientException) {
            throw DownloadFailedException(
                "Interactive authorization failed at endpoint $endpoint : ${e.message}",
                issuerErrorCode = e.issuerErrorCode,
                issuerErrorDescription = e.issuerErrorDescription,
                cause = e
            )
        } catch (e: Exception) {
            throw DownloadFailedException(
                "Interactive authorization failed at endpoint $endpoint : ${e.message}",
                cause = e
            )
        }

        return response.authorizationCode
            ?: throw DownloadFailedException(
                "Authorization failed: code not received from interactive authorization endpoint $endpoint. Error : ${response.error}, Description: ${response.errorDescription}",
                issuerErrorCode = response.error,
                issuerErrorDescription = response.errorDescription
            )
    }

    private suspend fun obtainAuthorizationCodeViaAuthorizationEndpoint(
        authorizationServerMetadata: AuthorizationServerMetadata,
         request: AuthorizationCodeCredentialRequest,
        pkceSession: PKCESessionManager.PKCESession,
    ): String {
        val configuration = request.configuration
        val options = request.options

        val authorizationEndpoint = authorizationServerMetadata.authorizationEndpoint
            ?: throw DownloadFailedException(
                "Missing authorization endpoint for issuer ${issuerMetadata.credentialIssuer}"
            )

        val redirectToWebAuthMethod =
            configuration.authorizationMethods
                .firstOrNull { it is AuthorizationMethod.RedirectToWeb } as? AuthorizationMethod.RedirectToWeb

        if (redirectToWebAuthMethod != null) {
             configuration.authorizationMethods
                .firstOrNull { it is AuthorizationMethod.RedirectToWeb }
                as? AuthorizationMethod.RedirectToWeb

        if (redirectToWebAuthMethod == null) {
            throw DownloadFailedException(
                "No authorization method available to obtain authorization code from " +
                    authorizationEndpoint,
            )
        }

            logger.info(
                "Using non-interactive authorization endpoint: $authorizationEndpoint " +
                    "(redirect_to_web) for issuer=${issuerMetadata.credentialIssuer}"
            )

            val requestData = ImplicitAuthorizationRequestData(
                authorizeUrl = authorizationEndpoint,
                clientMetadata = clientMetadata,
                pkceSession = pkceSession,
                scope = issuerMetadata.scope,
                dpopJkt = dpopManager.jwkThumbprint(),
                pushedAuthorizationRequestEndpoint =
                    authorizationServerMetadata.pushedAuthorizationRequestEndpoint,
                requirePushedAuthorizationRequests =
                    authorizationServerMetadata.requirePushedAuthorizationRequests
            )

            val response = try {
                RedirectToWebAuthorizationMethodService(redirectToWebAuthMethod.openWebPage)
                    .authorizeUser(requestData)

            } catch (e: VCIClientException) {
                throw DownloadFailedException(
                    "Authorization failed at authorization endpoint $authorizationEndpoint: ${e.message}",
                    issuerErrorCode = e.issuerErrorCode,
                    issuerErrorDescription = e.issuerErrorDescription,
                    cause = e
                )
            } catch (e: Exception) {
                throw DownloadFailedException(
                    "Authorization failed at authorization endpoint $authorizationEndpoint: ${e.message}",
                    cause = e
                )
            }
            return response.authorizationCode
                ?: throw DownloadFailedException(
                    "Authorization code not received from non-interactive authorization endpoint" + authorizationEndpoint,
                )
        } 
    }

    private suspend fun resolveNonce(
        issuerMetadata: IssuerMetadata,
        timeoutInMillis: Long,
        dpopManager: DPoPManager,
    ): String? {
        return nonceService.fetchNonce(
            issuerMetadata = issuerMetadata,
            timeoutInMillis = timeoutInMillis,
            dpopManager = dpopManager
        )
    }
}
