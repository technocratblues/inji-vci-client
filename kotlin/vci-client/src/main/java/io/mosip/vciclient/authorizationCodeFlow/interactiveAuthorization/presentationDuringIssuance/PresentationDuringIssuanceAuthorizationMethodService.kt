package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.presentationDuringIssuance

import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.wallet.Credential
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.AuthorizationMethodService
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.InteractionType
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request.AuthorizationRequestData
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.response.AuthorizationResponse
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.constants.Constants.APPLICATION_X_WWW_FORM_URLENCODED
import io.mosip.vciclient.constants.Constants.CONTENT_TYPE
import io.mosip.vciclient.exception.InteractiveAuthorizationException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.logging.Logger

class PresentationDuringIssuanceAuthorizationMethodService : AuthorizationMethodService {
    private val selectCredentialsForPresentation: suspend (ovpRequest: AuthorizationRequest) -> Map<String, List<Credential>>
    private val signVerifiablePresentation: suspend (
        payload: List<UnsignedVPToken>,
    ) -> List<VPTokenSigningResult>
    private val traceabilityId: String?
    val openid4vpWalletConfig: WalletConfig
    private val openId4vp: OpenID4VP

    private val logTag: String
    private val logger: Logger

    constructor(
        selectCredentialsForPresentation: suspend (ovpRequest: AuthorizationRequest) -> Map<String, List<Credential>>,
        signVerifiablePresentation: suspend (
            payload: List<UnsignedVPToken>,
        ) -> List<VPTokenSigningResult>,
        traceabilityId: String? = null,
        openid4vpWalletConfig: WalletConfig,
        openId4vp: OpenID4VP? = null,
    ) {
        this.selectCredentialsForPresentation = selectCredentialsForPresentation
        this.signVerifiablePresentation = signVerifiablePresentation
        this.traceabilityId = traceabilityId
        this.openid4vpWalletConfig = openid4vpWalletConfig
        this.openId4vp = openId4vp ?: OpenID4VP(
            traceabilityId = traceabilityId ?: "",
            walletConfig = openid4vpWalletConfig
        )
        this.logTag = Util.getLogTag(javaClass.simpleName, traceabilityId)
        this.logger = Logger.getLogger(logTag)
    }

   override fun type(): String = InteractionType.OpenId4VpPresentationIAE.value
    override suspend fun authorizeUser(
        requestData: AuthorizationRequestData
    ): AuthorizationResponse {

        if (requestData !is PresentationDuringIssuanceRequestData) {
            throw InteractiveAuthorizationException(
                "Expected PresentationDuringIssuanceRequestData"
            )
        }

        var vpResponse: Map<String, Any>

        try {
            try {
                val authorizationRequest =
                    validatePresentationRequest(requestData.ovpRequest)

                vpResponse = handlePresentation(authorizationRequest)

            } catch (error: Exception) {
                logger.warning("Error during presentation handling: ${error.message}")
                vpResponse = openId4vp.constructErrorInfo(error)
            }

            return sendOVPAuthorizationResponseToIssuer(
                iar = requestData.iar,
                authSession = requestData.authSession,
                vpResponse = vpResponse
            )
        } catch (ex: InteractiveAuthorizationException) {
            throw ex
        } catch (ex: VCIClientException) {
            throw InteractiveAuthorizationException(
                "Error during presentation authorization: ${ex.message}",
                cause = ex,
                issuerErrorCode = ex.issuerErrorCode,
                issuerErrorDescription = ex.issuerErrorDescription
            )
        } catch (ex: Exception) {
            throw InteractiveAuthorizationException(
                "Unexpected error during interactive authorization: ${ex.message}",
                cause = ex
            )
        }

    }


    private fun validatePresentationRequest(request: Map<String, Any>): AuthorizationRequest {
        val authorizationRequest = openId4vp.authenticateVerifier(request)
       if (
    authorizationRequest.responseMode !in listOf(
        "iar-post",
        "iar-post.jwt",
        "iae_post",
        "iae_post.jwt"
    )
) {
    throw IllegalArgumentException(
        "response_mode must be 'iar-post', 'iar-post.jwt', 'iae_post' or 'iae_post.jwt'"
    )
}
        return authorizationRequest
    }

    private suspend fun handlePresentation(vpRequest: AuthorizationRequest): Map<String, Any> {
        val selectedCredentials = selectCredentialsForPresentation(vpRequest)

        if (selectedCredentials.isEmpty()) {
            throw OpenID4VPExceptions.AccessDenied(
                "No credentials selected by user",
                className = "PresentationDuringIssuanceAuthorizationMethodService",
            )
        }

        val unsignedVpTokens = openId4vp.constructUnsignedVPToken(
            selectedCredentials = selectedCredentials,
        )

        val signedVpTokens = signVerifiablePresentation(unsignedVpTokens)

        return openId4vp.constructVPResponse(
            vpTokenSigningResults = signedVpTokens
        )
    }


    private suspend fun sendOVPAuthorizationResponseToIssuer(
        iar: String,
        authSession: String,
        vpResponse: Map<String, Any>
    ): AuthorizationResponse {
        val responseBody = mapOf(
            "auth_session" to authSession,
            "openid4vp_response" to JsonUtils.serialize(vpResponse)
        )

        val networkResponse = try {
            withContext(Dispatchers.IO) {
                NetworkManager.sendRequest(
                    url = iar,
                    method = HttpMethod.POST,
                    bodyParams = responseBody,
                    headers = mapOf(CONTENT_TYPE to APPLICATION_X_WWW_FORM_URLENCODED)
                )
            }

        } catch (ex: InteractiveAuthorizationException) {
            throw ex
        } catch (ex: VCIClientException) {
            throw InteractiveAuthorizationException(
                "Error while posting VP response: ${ex.message}",
                cause = ex,
                issuerErrorCode = ex.issuerErrorCode,
                issuerErrorDescription = ex.issuerErrorDescription
            )
        } catch (ex: Exception) {
            throw InteractiveAuthorizationException(
                "Unexpected error while posting VP response: ${ex.message}",
                cause = ex
            )
        }

        return JsonUtils.deserialize(networkResponse.body, AuthorizationResponse::class.java)
            ?: throw InteractiveAuthorizationException("Issuer response deserialization failed")
    }
}

