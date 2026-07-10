package io.mosip.vciclient.authorizationServer

import com.google.gson.annotations.SerializedName

data class AuthorizationServerMetadata(
    @SerializedName("issuer")
    val issuer: String,

    @SerializedName("grant_types_supported")
    val grantTypesSupported: List<String>? = null,

    @SerializedName("token_endpoint")
    val tokenEndpoint: String? = null,

    @SerializedName("authorization_endpoint")
    val authorizationEndpoint: String? = null,

    @SerializedName("interactive_authorization_endpoint")
    val interactiveAuthorizationEndpoint: String? = null,

    @SerializedName("require_interactive_authorization_request")
val requireInteractiveAuthorizationRequest: Boolean? = null
)