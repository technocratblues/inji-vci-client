package io.mosip.vciclient.authorizationServer

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.AuthorizationResponseType
import io.mosip.vciclient.constants.CodeChallengeMethod
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.constants.Constants.APPLICATION_X_WWW_FORM_URLENCODED
import io.mosip.vciclient.constants.Constants.CONTENT_TYPE
import io.mosip.vciclient.exception.PushedAuthorizationRequestException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.logging.Logger


data class PushedAuthorizationClientDetails(
    val clientId: String,
    val redirectUri: String,
    val scope: String? = null,
)

data class PushedAuthorizationSecurityDetails(
    val codeChallenge: String,
    val state: String,
    val nonce: String,
    val dpopJkt: String? = null,
    val codeChallengeMethod: CodeChallengeMethod = CodeChallengeMethod.S256,
    val responseType: AuthorizationResponseType = AuthorizationResponseType.CODE,
)

data class PushedAuthorizationRequestOptions(
    val clientAuthParams: Map<String, String> = emptyMap(),
    val timeoutMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
)

data class PushedAuthorizationRequest(
    val parEndpoint: String,
    val client: PushedAuthorizationClientDetails,
    val security: PushedAuthorizationSecurityDetails,
    val options: PushedAuthorizationRequestOptions = PushedAuthorizationRequestOptions(),
)

class PushedAuthorizationRequestService( 
private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
){
    private val logger = Logger.getLogger(javaClass.simpleName)

    
    suspend fun pushAuthorizationRequest(
        request: PushedAuthorizationRequest,
    ): PushedAuthorizationResponse = withContext(ioDispatcher) {
        val params = mutableMapOf<String, String>()

        params.putAll(clientAuthParams)
        params["response_type"] = responseType.value
        params["client_id"] = clientId
        params["redirect_uri"] = redirectUri
        params["code_challenge"] = codeChallenge
        params["code_challenge_method"] = codeChallengeMethod.value
        params["state"] = state
        params["nonce"] = nonce
        if (!request.client.scope.isNullOrBlank()) {
            params["scope"] = request.client.scope
        }
        if (!request.security.dpopJkt.isNullOrBlank()) {
            params["dpop_jkt"] = request.security.dpopJkt
        }

        logger.info("Pushing authorization request to PAR endpoint: $parEndpoint")

        val response = try {
            NetworkManager.sendRequest(
                url = parEndpoint,
                method = HttpMethod.POST,
                headers = mapOf(CONTENT_TYPE to APPLICATION_X_WWW_FORM_URLENCODED),
                bodyParams = params,
                timeoutMillis = timeoutMillis,
            )
        } catch (e: VCIClientException) {
            throw PushedAuthorizationRequestException(
                "PAR request failed at $parEndpoint: ${e.message}",
                issuerErrorCode = e.issuerErrorCode,
                issuerErrorDescription = e.issuerErrorDescription,
                cause = e,
            )
        } catch (e: Exception) {
            throw PushedAuthorizationRequestException(
                "PAR request failed at $parEndpoint: ${e.message}",
                issuerErrorCode = null,
                issuerErrorDescription = null,
                cause = e,
            )
        }

        val parResponse = JsonUtils.deserialize(
            response.body, PushedAuthorizationResponse::class.java
        )
        if (parResponse == null || parResponse.requestUri.isNullOrBlank()) {
            throw PushedAuthorizationRequestException(
                "Invalid PAR response from $parEndpoint: missing request_uri"
            )
        }
        parResponse
    }
}
