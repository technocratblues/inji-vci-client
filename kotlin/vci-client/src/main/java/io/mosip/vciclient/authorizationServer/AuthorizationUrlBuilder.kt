package io.mosip.vciclient.authorizationServer

import io.mosip.vciclient.constants.CodeChallengeMethod
import io.mosip.vciclient.constants.AuthorizationResponseType
import java.net.URLEncoder


data class AuthorizationClientDetails(
    val clientId: String,
    val redirectUri: String,
    val scope: String,
)

data class AuthorizationSecurityDetails(
    val state: String,
    val codeChallenge: String,
    val nonce: String,
    val dpopJkt: String,
    val codeChallengeMethod: CodeChallengeMethod = CodeChallengeMethod.S256,
)

data class AuthorizationRequest(
    val baseUrl: String,
    val client: AuthorizationClientDetails,
    val security: AuthorizationSecurityDetails,
    val responseType: AuthorizationResponseType = AuthorizationResponseType.CODE,
)

object AuthorizationUrlBuilder {
    fun buildAuthorizationRequestUrl(
      request: AuthorizationRequest
    ): String {
        return buildString {
            append(baseUrl)
            append("?client_id=").append(encode(clientId))
            append("&redirect_uri=").append(encode(redirectUri))
            append("&response_type=").append(encode(responseType.value))
            append("&scope=").append(encode(scope))
            append("&state=").append(encode(state))
            append("&code_challenge=").append(encode(codeChallenge))
            append("&code_challenge_method=").append(encode(codeChallengeMethod.value))
            append("&nonce=").append(encode(nonce))
            append("&dpop_jkt=").append(encode(dpopJkt))
        }
    }

    fun buildAuthorizationRequestUrlWithRequestUri(
        baseUrl: String,
        clientId: String,
        requestUri: String,
    ): String {
        return buildString {
            append(baseUrl)
            append("?client_id=").append(encode(clientId))
            append("&request_uri=").append(encode(requestUri))
        }
    }

    private fun encode(value: String): String =
        URLEncoder.encode(value, "UTF-8")
}
