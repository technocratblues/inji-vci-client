package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.presentationDuringIssuance

import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.InteractionType
import com.google.gson.annotations.SerializedName
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.response.InteractionResponse

data class PresentationInteractionResponse(
    @SerializedName("status")
    override val status: String,
    @SerializedName("type")
    override val type: String,
    @SerializedName("auth_session")
    override val authSession: String,
    @SerializedName("openid4vp_request")
    val openid4vpRequest: Map<String, Any>
) : InteractionResponse(status, type, authSession) {

    override fun validate() {
        require(
            type == InteractionType.OpenId4VpPresentation.value ||
                type == InteractionType.OpenId4VpPresentationIAE.value
        ) {
            "Unsupported interaction type: $type. Expected OpenId4VpPresentation or OpenId4VpPresentationIAE."
        }

        require(openid4vpRequest.isNotEmpty()) {
            "openid4vpRequest must not be empty"
        }
    }
}