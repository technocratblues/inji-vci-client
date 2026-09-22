package io.mosip.vciclient.token

import io.mosip.vciclient.constants.GrantType
import io.mosip.vciclient.constants.TokenResponseCallback
import io.mosip.vciclient.dpop.DPoPManager

data class TokenRequestParams(
    val grantType: GrantType,
    val getTokenResponse: TokenResponseCallback,
    val tokenEndpoint: String,
    val preAuthCode: String? = null,
    val txCode: String? = null,
    val authCode: String? = null,
    val clientId: String? = null,
    val redirectUri: String? = null,
    val codeVerifier: String? = null,
    val dpopManager: DPoPManager = DPoPManager(),
)

class TokenService {
    suspend fun getAccessToken(
        getTokenResponse: TokenResponseCallback,
        tokenEndpoint: String,
        preAuthCode: String,
        txCode: String? = null,
        dpopManager: DPoPManager = DPoPManager(),
    ): TokenResponse = obtainAccessToken(
        grantType = GrantType.PRE_AUTHORIZED,
        getTokenResponse = getTokenResponse,
        tokenEndpoint = tokenEndpoint,
        preAuthCode = preAuthCode,
        txCode = txCode,
        dpopManager = dpopManager
    )

    suspend fun getAccessToken(
        getTokenResponse: TokenResponseCallback,
        tokenEndpoint: String,
        authCode: String,
        clientId: String? = null,
        redirectUri: String? = null,
        codeVerifier: String? = null,
        dpopManager: DPoPManager = DPoPManager(),
    ): TokenResponse = obtainAccessToken(
        TokenRequestParams(
        grantType = GrantType.AUTHORIZATION_CODE,
        getTokenResponse = getTokenResponse,
        tokenEndpoint = tokenEndpoint,
        authCode = authCode,
        clientId = clientId,
        redirectUri = redirectUri,
        codeVerifier = codeVerifier,
        dpopManager = dpopManager
    )
    )

    private suspend fun obtainAccessToken(
        params: TokenRequestParams
    ): TokenResponse {
        val dpopProof = if (params.dpopManager.isInitialized) {
            params.dpopManager.generateTokenProof()
        } else {
            null
        }
        val tokenRequest = TokenRequest(
            grantType,
            tokenEndpoint,
            authCode,
            preAuthCode,
            txCode,
            clientId,
            redirectUri,
            codeVerifier,
            dpopProof
        )
        
            getTokenResponse(tokenRequest )
        }
}