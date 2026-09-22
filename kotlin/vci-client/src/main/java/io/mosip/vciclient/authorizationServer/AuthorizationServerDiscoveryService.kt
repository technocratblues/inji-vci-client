package io.mosip.vciclient.authorizationServer

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.common.WellKnownUrl
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.exception.AuthorizationServerDiscoveryException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
//import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.logging.Logger

private const val OAUTH_WELL_KNOWN_URI_SUFFIX = "/.well-known/oauth-authorization-server"
private const val OPENID_WELL_KNOWN_URI_SUFFIX = "/.well-known/openid-configuration"

class AuthorizationServerDiscoveryService( 
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
){
    private val logger = Logger.getLogger(javaClass.simpleName)

    /**
     * Discovers the authorization server metadata by querying the well-known endpoints
     * (oauth-authorization-server first, then openid-configuration), trying each candidate URL
     * until one returns parseable metadata.
     */
    suspend fun discover(baseUrl: String): AuthorizationServerMetadata = withContext(ioDispatcher) {
        for (wellKnownUrl in buildCandidateWellKnownUrls(baseUrl)) {
            try {
                val response = NetworkManager.sendRequest(
                    url = wellKnownUrl,
                    method = HttpMethod.GET,
                    timeoutMillis = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS
                )
                if (response.body.isNotBlank()) {
                    JsonUtils.deserialize(response.body, AuthorizationServerMetadata::class.java)
                        ?.let { return@withContext it }
                }
            } catch (e: Exception) {
                logger.warning(
                    "Authorization server discovery failed at $wellKnownUrl, trying next candidate: ${e.message}"
                )
            }
        }

        throw AuthorizationServerDiscoveryException(
            "Failed to discover authorization server metadata at all well-known endpoints"
        )
    }

    /**
     * Candidate well-known URLs in priority order: the [WellKnownUrl] inserted form followed by
     * the legacy append form, for both well-known suffixes.
     */
    internal fun buildCandidateWellKnownUrls(baseUrl: String): List<String> {
        val normalized = baseUrl.trimEnd('/')
        val candidates = mutableListOf<String>()

        runCatching {
            candidates.add(WellKnownUrl.insertSuffix(normalized, OAUTH_WELL_KNOWN_URI_SUFFIX))
            candidates.add(WellKnownUrl.insertSuffix(normalized, OPENID_WELL_KNOWN_URI_SUFFIX))
        }

        val appendedOauthUrl = "$normalized$OAUTH_WELL_KNOWN_URI_SUFFIX"
        if (appendedOauthUrl !in candidates) {
            candidates.add(appendedOauthUrl)
            candidates.add("$normalized$OPENID_WELL_KNOWN_URI_SUFFIX")
        }

        return candidates
    }
}
