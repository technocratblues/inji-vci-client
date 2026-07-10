package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler

import io.mosip.vciclient.authorizationCodeFlow.AuthorizationMethod
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.presentationDuringIssuance.PresentationInteractionResponse
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.presentationDuringIssuance.PresentationDuringIssuanceRequestData
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.presentationDuringIssuance.PresentationDuringIssuanceAuthorizationMethodService
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request.AuthorizationDetail
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request.IARInitialRequestBody
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.response.AuthorizationResponse
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.Constants.APPLICATION_X_WWW_FORM_URLENCODED
import io.mosip.vciclient.constants.Constants.CONTENT_TYPE
import io.mosip.vciclient.exception.InteractiveAuthorizationException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import io.mosip.vciclient.pkce.PKCESessionManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.logging.Logger

class InteractiveAuthorizationHandler {

    private val logger = Logger.getLogger(javaClass.simpleName)

    suspend fun handle(
        endpoint: String,
        clientMetadata: ClientMetadata,
        credentialConfigurationId: String,
        authorizationMethods: List<AuthorizationMethod>,
        pkceSession: PKCESessionManager.PKCESession,
        traceabilityId: String? = null
    ): AuthorizationResponse {

        return try {
            //interaction types supported will be extracted from authmethods once we start supporting redirect-to-web
            val interactionTypesSupported = authorizationMethods
                .filter { it.type != InteractionType.RedirectToWeb }
                .flatMap {  
                    if (it is AuthorizationMethod.PresentationDuringIssuance) {
            listOf(
                InteractionType.OpenId4VpPresentation.value,
                InteractionType.OpenId4VpPresentationIAE.value
            )
        } else {
            listOf(it.type.value)
        }
    }
    .distinct()
    
            if (interactionTypesSupported.isEmpty()) {
                throw InteractiveAuthorizationException("No supported interaction types found in authorization methods")
            }

            val requestMap = buildInitialIarRequest(
                clientMetadata,
                credentialConfigurationId,
                pkceSession,
                interactionTypesSupported
            )

            val response = withContext(Dispatchers.IO) {
                NetworkManager.sendRequest(
                    url = endpoint,
                    method = HttpMethod.POST,
                    bodyParams = requestMap,
                    headers = mapOf(CONTENT_TYPE to APPLICATION_X_WWW_FORM_URLENCODED)
                )
            }

          when (val type = extractTypeAndThrowIfError(response.body)) {
    InteractionType.OpenId4VpPresentation.value,
    InteractionType.OpenId4VpPresentationIAE.value ->
        handlePresentationInteraction(
            response.body,
            authorizationMethods,
            endpoint,
            traceabilityId
        )

    else ->
        throw InteractiveAuthorizationException("Unsupported interaction type: $type")
}
        } catch (e: InteractiveAuthorizationException) {
            logger.warning("Interactive authorization failed: ${e.message}")
            throw e
        } catch (e: VCIClientException) {
            logger.severe("Interactive authorization failed: ${e.message}")
            throw InteractiveAuthorizationException(
                "Interactive authorization failed: ${e.message}",
                issuerErrorCode = e.issuerErrorCode,
                issuerErrorDescription = e.issuerErrorDescription,
                cause = e
            )
        } catch (e: Exception) {
            logger.severe("Unexpected error during interactive authorization: ${e.message}")
            throw InteractiveAuthorizationException(
                "Unexpected error during interactive authorization: ${e.message}",
                cause = e
            )
        }
    }

    private fun buildInitialIarRequest(
        clientMetadata: ClientMetadata,
        credentialConfigId: String,
        pkce: PKCESessionManager.PKCESession,
        interactionTypesSupported: List<String>
    ): Map<String, String> {
        val details = listOf(
            AuthorizationDetail(
                type = "openid_credential",
                credentialConfigurationId = credentialConfigId
            )
        )

        return IARInitialRequestBody(
            clientId = clientMetadata.clientId,
            codeChallenge = pkce.codeChallenge,
            redirectUri = clientMetadata.redirectUri,
            authorizationDetails = details,
            interactionTypesSupported = interactionTypesSupported
        ).toFormMap()
    }

    private fun extractTypeAndThrowIfError(responseBody: String): String {
        var json: JSONObject
        try {
            json = JSONObject(responseBody)
        } catch (_: Exception) {
            throw InteractiveAuthorizationException("Invalid JSON in interaction response from authorization server")
        }
        if (json.has("type")) {
            return json.getString("type")
        }
        if (json.has("error")) {
            val error = json.optString("error")
            val errorDescription = json.optString("error_description")

            throw InteractiveAuthorizationException(
                message = buildString {
                    append("authorization server error: $error")
                    if (errorDescription.isNotBlank()) {
                        append(" - $errorDescription")
                    }
                },
                error,
                errorDescription
            )
        } else {
            throw InteractiveAuthorizationException("Missing 'type' in interaction response from authorization server")
        }
    }


    private suspend fun handlePresentationInteraction(
        presentationInteractionResponse: String,
        authorizationMethods: List<AuthorizationMethod>,
        endpoint: String,
        traceabilityId: String? = null
    ): AuthorizationResponse {

        val parsedPresentationInteractionResponse = JsonUtils.deserialize(
            presentationInteractionResponse,
            PresentationInteractionResponse::class.java
        )
            ?: throw InteractiveAuthorizationException("Failed to parse presentation interaction response")

        try {
            parsedPresentationInteractionResponse.validate()
        } catch (e: Exception) {
            throw InteractiveAuthorizationException(
                "Invalid presentation interaction response: ${e.message}",
                cause = e
            )
        }

        val presentationMethod = authorizationMethods
            .filterIsInstance<AuthorizationMethod.PresentationDuringIssuance>()
            .firstOrNull()
            ?: throw InteractiveAuthorizationException("Presentation callback missing")

        val request = PresentationDuringIssuanceRequestData(
            ovpRequest = parsedPresentationInteractionResponse.openid4vpRequest,
            authSession = parsedPresentationInteractionResponse.authSession,
            iar = endpoint
        )

        val authorizationService = PresentationDuringIssuanceAuthorizationMethodService(
            selectCredentialsForPresentation = presentationMethod.selectCredentialsForPresentation,
            signVerifiablePresentation = presentationMethod.signVerifiablePresentation,
            openid4vpWalletConfig = presentationMethod.openid4vpWalletConfig,
            traceabilityId = traceabilityId
        )

        return authorizationService.authorizeUser(request)
    }
}
