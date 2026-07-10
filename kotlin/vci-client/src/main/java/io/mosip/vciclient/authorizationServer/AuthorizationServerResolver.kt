package io.mosip.vciclient.authorizationServer

import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.exception.AuthorizationServerDiscoveryException
import io.mosip.vciclient.constants.GrantType
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

class AuthorizationServerResolver {
    suspend fun resolveForPreAuth(
        issuerMetadata: IssuerMetadata,
        credentialOffer: CredentialOffer,
    ): AuthorizationServerMetadata {
        return resolveAuthorizationServer(
            offerGrantAuthorizationServer = credentialOffer.grants?.preAuthorizedGrant?.authorizationServer,
            issuerMetadata,
            expectedGrantType = GrantType.PRE_AUTHORIZED.value,
            issuerMetadata.credentialIssuer
        )
    }

    suspend fun resolveForAuthCode(
        issuerMetadata: IssuerMetadata,
        credentialOffer: CredentialOffer? = null,
    ): AuthorizationServerMetadata {
        return resolveAuthorizationServer(
            offerGrantAuthorizationServer = credentialOffer?.grants?.authorizationCodeGrant?.authorizationServer,
            issuerMetadata,
            expectedGrantType = GrantType.AUTHORIZATION_CODE.value,
            credentialIssuer = issuerMetadata.credentialIssuer
        )
    }

    private suspend fun resolveAuthorizationServer(
        offerGrantAuthorizationServer: String?,
        issuerMetadata: IssuerMetadata,
        expectedGrantType: String,
        credentialIssuer: String,
    ): AuthorizationServerMetadata {
        val authorizationServers = issuerMetadata.authorizationServers
        return when {
           authorizationServers?.size == 1 -> {
    discoverAndValidate(authorizationServers.first(), expectedGrantType)
}
            !offerGrantAuthorizationServer.isNullOrBlank() -> {
                discoverAndValidate(offerGrantAuthorizationServer, expectedGrantType)
            }

            !authorizationServers.isNullOrEmpty() -> {
                resolveFirstValid(authorizationServers, expectedGrantType)
            }

            else -> {
                discoverAndValidate(credentialIssuer, expectedGrantType)
            }
        }
    }

    private suspend fun discoverAndValidate(
        authorizationServerUrl: String,
        expectedGrantType: String,
    ): AuthorizationServerMetadata {

            val normalizedAuthorizationServerUrl = authorizationServerUrl.trim()

val authorizationServerMetadata =
    AuthorizationServerDiscoveryService().discover(normalizedAuthorizationServerUrl)

if (
    normalizedAuthorizationServerUrl.isNotEmpty() &&
    authorizationServerMetadata.issuer != normalizedAuthorizationServerUrl
) {
    throw AuthorizationServerDiscoveryException(
        "Issuer mismatch: Expected '$normalizedAuthorizationServerUrl', got '${authorizationServerMetadata.issuer}'"
    )
}
        if ((expectedGrantType !in ((authorizationServerMetadata.grantTypesSupported) ?: listOf(
                GrantType.AUTHORIZATION_CODE.value, GrantType.IMPLICIT.value
            )) && expectedGrantType != GrantType.PRE_AUTHORIZED.value)
        ) {
            throw AuthorizationServerDiscoveryException("Grant type '$expectedGrantType' not supported by auth server.")
        }

        return authorizationServerMetadata
    }

    private suspend fun resolveFirstValid(
        authorizationServers: List<String>,
        expectedGrantType: String,
    ): AuthorizationServerMetadata = coroutineScope {
        val deferreds = authorizationServers.map { authorizationServer ->
            async {
                runCatching {
                    discoverAndValidate(authorizationServer, expectedGrantType)
                }.getOrNull()
            }
        }

        deferreds.firstNotNullOfOrNull { it.await() }
            ?: throw AuthorizationServerDiscoveryException("None of the authorization servers responded with valid metadata.")
    }

}
