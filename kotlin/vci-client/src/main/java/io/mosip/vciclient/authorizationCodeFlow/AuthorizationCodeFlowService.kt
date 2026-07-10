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
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.nonce.NonceService
import io.mosip.vciclient.pkce.PKCESessionManager
import io.mosip.vciclient.proof.jwt.JWTProof
import io.mosip.vciclient.token.TokenResponse
import io.mosip.vciclient.token.TokenService
import java.util.logging.Logger

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
        issuerMetadata: IssuerMetadata,
        credentialConfigurationId: String,
        clientMetadata: ClientMetadata,
        getTokenResponse: TokenResponseCallback,
        getProofs: ProofsCallback,
        authorizationMethods: List<AuthorizationMethod>,
        credentialOffer: CredentialOffer? = null,
        downloadTimeOutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        jwtProofAlgorithmsSupported: List<String>,
        traceabilityId: String? = null,
    ): CredentialResponse {
        return executeRequestCredentials(
            issuerMetadata = issuerMetadata,
            credentialConfigurationId = credentialConfigurationId,
            clientMetadata = clientMetadata,
            getTokenResponse = getTokenResponse,
            authorizationMethods = authorizationMethods,
            credentialOffer = credentialOffer,
            downloadTimeOutInMillis = downloadTimeOutInMillis,
            traceabilityId = traceabilityId,
        ) { token ->
            val nonce = resolveNonce(
                issuerMetadata = issuerMetadata,
                timeoutInMillis = downloadTimeOutInMillis
            )
            val proofs = try {
                getProofs(
                    issuerMetadata.credentialIssuer,
                    nonce,
                    jwtProofAlgorithmsSupported
                )
            } catch (e: Exception) {
                throw DownloadFailedException(
                    "Failed to obtain proofs from callback: ${e.message}",
                    cause = e
                )
            }

            credentialExecutor.requestCredential(
                issuerMetadata = issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                proofs = proofs,
                accessToken = token.accessToken,
                downloadTimeoutInMillis = downloadTimeOutInMillis
            )
        }
    }

    suspend fun requestCredentialsDraft13(
        issuerMetadata: IssuerMetadata,
        credentialConfigurationId: String,
        clientMetadata: ClientMetadata,
        getTokenResponse: TokenResponseCallback,
        getProofJwt: ProofJwtCallback,
        authorizationMethods: List<AuthorizationMethod>,
        credentialOffer: CredentialOffer? = null,
        downloadTimeOutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        jwtProofAlgorithmsSupported: List<String>,
        traceabilityId: String? = null,
    ): CredentialResponseDraft13 {
        return executeRequestCredentials(
            issuerMetadata = issuerMetadata,
            credentialConfigurationId = credentialConfigurationId,
            clientMetadata = clientMetadata,
            getTokenResponse = getTokenResponse,
            authorizationMethods = authorizationMethods,
            credentialOffer = credentialOffer,
            downloadTimeOutInMillis = downloadTimeOutInMillis,
            traceabilityId = traceabilityId,
        ) { token ->
            val nonce = NonceService.extractNonceFromTokenResponse(token)
            val jwt = try {
                getProofJwt(
                    issuerMetadata.credentialIssuer,
                    nonce,
                    jwtProofAlgorithmsSupported
                )
            } catch (e: Exception) {
                throw DownloadFailedException(
                    "Failed to obtain proof JWT from callback: ${e.message}",
                    cause = e
                )
            }

            credentialExecutor.requestCredentialDraft13(
                issuerMetadata = issuerMetadata,
                credentialConfigurationId = credentialConfigurationId,
                proof = JWTProof(jwt),
                accessToken = token.accessToken,
                downloadTimeoutInMillis = downloadTimeOutInMillis
            )
        }
    }

    private suspend fun <Response> executeRequestCredentials(
        issuerMetadata: IssuerMetadata,
        credentialConfigurationId: String,
        clientMetadata: ClientMetadata,
        getTokenResponse: TokenResponseCallback,
        authorizationMethods: List<AuthorizationMethod>,
        credentialOffer: CredentialOffer?,
        downloadTimeOutInMillis: Long,
        traceabilityId: String?,
        requestCredential: suspend (TokenResponse) -> Response?,
    ): Response {
        try {
            val pkceSession = pkceSessionManager.createSession()

            val authorizationServerMetadata = try {
                authorizationServerResolver.resolveForAuthCode(issuerMetadata, credentialOffer)
            } catch (e: DownloadFailedException) {
                throw e
            } catch (e: VCIClientException) {
                throw DownloadFailedException(
                    "Failed to resolve authorization server metadata for issuer ${issuerMetadata.credentialIssuer}: ${e.message} ",
                    issuerErrorCode = e.issuerErrorCode,
                    issuerErrorDescription = e.issuerErrorDescription,
                    cause = e
                )
            } catch (e: Exception) {
                throw DownloadFailedException(
                    "Failed to resolve authorization server metadata for issuer ${issuerMetadata.credentialIssuer}: ${e.message}",
                    cause = e
                )
            }

            val token = try {
                performAuthorizationAndGetToken(
                    authorizationServerMetadata = authorizationServerMetadata,
                    issuerMetadata = issuerMetadata,
                    clientMetadata = clientMetadata,
                    pkceSession = pkceSession,
                    getTokenResponse = getTokenResponse,
                    credentialConfigurationId = credentialConfigurationId,
                    authorizationMethods = authorizationMethods,
                    traceabilityId = traceabilityId
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
            )
        }
    }

    private suspend fun performAuthorizationAndGetToken(
        authorizationServerMetadata: AuthorizationServerMetadata,
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        pkceSession: PKCESessionManager.PKCESession,
        getTokenResponse: TokenResponseCallback,
        credentialConfigurationId: String,
        authorizationMethods: List<AuthorizationMethod>,
        traceabilityId: String? = null,
    ): TokenResponse {
        val tokenEndpoint = issuerMetadata.tokenEndpoint
            ?: authorizationServerMetadata.tokenEndpoint
            ?: throw DownloadFailedException(
                "Missing token endpoint for issuer ${issuerMetadata.credentialIssuer}"
            )

        val authCode = obtainAuthorizationCode(
            authorizationServerMetadata = authorizationServerMetadata,
            issuerMetadata = issuerMetadata,
            clientMetadata = clientMetadata,
            pkceSession = pkceSession,
            credentialConfigurationId = credentialConfigurationId,
            authorizationMethods = authorizationMethods,
            traceabilityId = traceabilityId
        )

        return try {
            tokenService.getAccessToken(
                getTokenResponse = getTokenResponse,
                tokenEndpoint = tokenEndpoint,
                authCode = authCode,
                clientId = clientMetadata.clientId,
                redirectUri = clientMetadata.redirectUri,
                codeVerifier = pkceSession.codeVerifier
            )
        } catch (e: Exception) {
            throw DownloadFailedException(
                "Failed to exchange authorization code for access token at $tokenEndpoint: ${e.message}",
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
    issuerMetadata: IssuerMetadata,
    clientMetadata: ClientMetadata,
    pkceSession: PKCESessionManager.PKCESession,
    credentialConfigurationId: String,
    authorizationMethods: List<AuthorizationMethod>,
    traceabilityId: String? = null,
): String {

    val interactiveEndpoint =
        authorizationServerMetadata.interactiveAuthorizationEndpoint?.trim()

    val hasInteractiveEndpoint = !interactiveEndpoint.isNullOrEmpty()

    if (
        authorizationServerMetadata.requireInteractiveAuthorizationRequest == true &&
        !hasInteractiveEndpoint
    ) {
        throw DownloadFailedException("Missing interactive authorization endpoint")
    }

    return if (hasInteractiveEndpoint) {
        try {
              obtainAuthorizationCodeViaInteractiveAuthorizationEndpoint(
                endpoint = interactiveEndpoint!!,
                issuerMetadata = issuerMetadata,
                clientMetadata = clientMetadata,
                pkceSession = pkceSession,
                credentialConfigurationId = credentialConfigurationId,
                authorizationMethods = authorizationMethods,
                traceabilityId = traceabilityId
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
                    issuerMetadata = issuerMetadata,
                    clientMetadata = clientMetadata,
                    pkceSession = pkceSession,
                    authorizationMethods = authorizationMethods
                )
            } else {
                throw e
            }
        }
    } else {
        obtainAuthorizationCodeViaAuthorizationEndpoint(
            authorizationServerMetadata = authorizationServerMetadata,
            issuerMetadata = issuerMetadata,
            clientMetadata = clientMetadata,
            pkceSession = pkceSession,
            authorizationMethods = authorizationMethods
        )
    }
}
private suspend fun obtainAuthorizationCodeViaInteractiveAuthorizationEndpoint(
    endpoint: String,
    issuerMetadata: IssuerMetadata,
    clientMetadata: ClientMetadata,
    pkceSession: PKCESessionManager.PKCESession,
    credentialConfigurationId: String,
    authorizationMethods: List<AuthorizationMethod>,
    traceabilityId: String? = null,
): String {
        val response = try {
            interactiveAuthorizationHandler.handle(
                endpoint = endpoint,
                clientMetadata = clientMetadata,
                credentialConfigurationId = credentialConfigurationId,
                authorizationMethods = authorizationMethods,
                pkceSession = pkceSession,
                traceabilityId = traceabilityId
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
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        pkceSession: PKCESessionManager.PKCESession,
        authorizationMethods: List<AuthorizationMethod>,
    ): String {
        val authorizationEndpoint = authorizationServerMetadata.authorizationEndpoint
            ?: throw DownloadFailedException(
                "Missing authorization endpoint for issuer ${issuerMetadata.credentialIssuer}"
            )

        val redirectToWebAuthMethod =
            authorizationMethods
                .firstOrNull { it is AuthorizationMethod.RedirectToWeb } as? AuthorizationMethod.RedirectToWeb

        if (redirectToWebAuthMethod != null) {
            logger.info(
                "Using non-interactive authorization endpoint: $authorizationEndpoint " +
                    "(redirect_to_web) for issuer=${issuerMetadata.credentialIssuer}"
            )

            val requestData = ImplicitAuthorizationRequestData(
                authorizeUrl = authorizationEndpoint,
                clientMetadata = clientMetadata,
                pkceSession = pkceSession,
                scope = issuerMetadata.scope
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
                    "Authorization code not received from non-interactive authorization endpoint $authorizationEndpoint"
                )
        } else {
            throw DownloadFailedException(
                "No authorization method available to obtain authorization code from $authorizationEndpoint"
            )
        }
    }

    private suspend fun resolveNonce(
        issuerMetadata: IssuerMetadata,
        timeoutInMillis: Long,
    ): String? {
        return nonceService.fetchNonce(
            issuerMetadata = issuerMetadata,
            timeoutInMillis = timeoutInMillis
        )
    }
}
