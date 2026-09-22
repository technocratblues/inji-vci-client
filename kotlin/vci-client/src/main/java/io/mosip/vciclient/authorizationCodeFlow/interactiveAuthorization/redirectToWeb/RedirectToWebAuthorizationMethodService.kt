package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.redirectToWeb

import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request.InitialRequest
import io.mosip.vciclient.authorizationCodeFlow.implicitAuthorization.ImplicitAuthorizationRequestData
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.AuthorizationMethodService
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request.AuthorizationRequestData
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.response.AuthorizationResponse
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.InteractionType
import io.mosip.vciclient.authorizationServer.AuthorizationUrlBuilder
import io.mosip.vciclient.authorizationServer.PushedAuthorizationRequestService
import io.mosip.vciclient.constants.OpenWebPageCallback
import io.mosip.vciclient.exception.InteractiveAuthorizationException
import io.mosip.vciclient.exception.PushedAuthorizationRequestException
import kotlinx.coroutines.CancellationException
import java.util.logging.Logger

class RedirectToWebAuthorizationMethodService(
    val openWebPage: OpenWebPageCallback,
    private val parService: PushedAuthorizationRequestService = PushedAuthorizationRequestService(),
) : AuthorizationMethodService {

    private val logger = Logger.getLogger(javaClass.simpleName)

    override fun type(): String {
        return InteractionType.RedirectToWeb.value
    }

    override suspend fun authorizeUser(requestData: AuthorizationRequestData): AuthorizationResponse {
        if (requestData !is ImplicitAuthorizationRequestData) {
            throw InteractiveAuthorizationException(
                "RedirectToWebAuthorizationHandler expects ImplicitAuthorizationRequestData " +
                        "but received ${requestData::class.simpleName}"
            )
        }

        val parEndpoint = requestData.pushedAuthorizationRequestEndpoint
        val isParRequired = requestData.requirePushedAuthorizationRequests ?: false

        val authUrl = if (isParRequired) {
            if (parEndpoint.isNullOrBlank()) {
                throw PushedAuthorizationRequestException(
                    "Authorization server requires pushed authorization requests " +
                            "but did not advertise a pushed_authorization_request_endpoint"
                )
            }
            buildAuthorizationUrlViaPushedRequest(requestData, parEndpoint)
        } else if (!parEndpoint.isNullOrBlank()) {
            try {
                buildAuthorizationUrlViaPushedRequest(requestData, parEndpoint)
            } catch (exception: CancellationException) {
                throw exception
            } catch (exception: Exception) {
                logger.warning(
                    "PAR attempt failed at $parEndpoint and PAR is not required by the " +
                            "authorization server, falling back to the standard " +
                            "authorization request: ${exception.message}"
                )
                buildStandardAuthorizationUrl(requestData)
            }
        } else {
            buildStandardAuthorizationUrl(requestData)
        }
        val authorizationResponse = openWebPage(authUrl)

        if (authorizationResponse.containsKey("error")) {
            val error = authorizationResponse["error"] as? String
            val errorDescription = authorizationResponse["error_description"] as? String
            return AuthorizationResponse(
                authorizationCode = null,
                status = "error",
                error = error,
                errorDescription = errorDescription,
                authSession = null
            )
        }

        val code = authorizationResponse["code"] as? String
            ?: throw InteractiveAuthorizationException("Missing authorization_code in successful redirect response")

        return AuthorizationResponse(
            authorizationCode = code,
            status = "success",
            error = null,
            errorDescription = null,
            authSession = authorizationResponse["auth_session"] as? String
        )
    }

    private suspend fun buildAuthorizationUrlViaPushedRequest(
        requestData: ImplicitAuthorizationRequestData,
        parEndpoint: String,
    ): String {
        val parResponse = parService.pushAuthorizationRequest(
            parEndpoint = parEndpoint,
            clientId = requestData.clientMetadata.clientId,
            redirectUri = requestData.clientMetadata.redirectUri,
            codeChallenge = requestData.pkceSession.codeChallenge,
            state = requestData.pkceSession.state,
            nonce = requestData.pkceSession.nonce,
            scope = requestData.scope,
            dpopJkt = requestData.dpopJkt
        )
        val requestUri = parResponse.requestUri
            ?: throw PushedAuthorizationRequestException(
                "PAR response from $parEndpoint did not contain a request_uri"
            )
        return AuthorizationUrlBuilder.buildAuthorizationRequestUrlWithRequestUri(
            baseUrl = requestData.authorizeUrl,
            clientId = requestData.clientMetadata.clientId,
            requestUri = requestUri
        )
    }

    private fun buildStandardAuthorizationUrl(
        requestData: ImplicitAuthorizationRequestData,
    ): String {
        return AuthorizationUrlBuilder.buildAuthorizationRequestUrl(
            baseUrl = requestData.authorizeUrl,
            clientId = requestData.clientMetadata.clientId,
            redirectUri = requestData.clientMetadata.redirectUri,
            scope = requestData.scope,
            state = requestData.pkceSession.state,
            codeChallenge = requestData.pkceSession.codeChallenge,
            nonce = requestData.pkceSession.nonce,
            dpopJkt = requestData.dpopJkt
        )
    }
}

