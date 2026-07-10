package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler

enum class InteractionType(val value: String) {
    RedirectToWeb("redirect_to_web"),
    OpenId4VpPresentation("openid4vp_presentation"),
    OpenId4VpPresentationIAE("urn:openid:dcp:iae:openid4vp_presentation")
}