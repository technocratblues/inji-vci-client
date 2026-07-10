package io.mosip.vciclient.authorizationCodeFlow

import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.InteractionType
import io.mosip.vciclient.constants.SelectCredentialsForPresentationCallback
import io.mosip.vciclient.constants.OpenWebPageCallback
import io.mosip.vciclient.constants.SignVerifiablePresentationCallback

sealed class AuthorizationMethod(val type: InteractionType) {

    class RedirectToWeb(
        val openWebPage: OpenWebPageCallback
    ) : AuthorizationMethod(InteractionType.RedirectToWeb)

    class PresentationDuringIssuance(
        val openid4vpWalletConfig: WalletConfig = WalletConfig(),
        val selectCredentialsForPresentation: SelectCredentialsForPresentationCallback,
        val signVerifiablePresentation: SignVerifiablePresentationCallback
    ) : AuthorizationMethod(type = InteractionType.OpenId4VpPresentationIAE)
}
