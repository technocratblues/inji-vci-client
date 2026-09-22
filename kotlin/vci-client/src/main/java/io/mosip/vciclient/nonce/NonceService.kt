package io.mosip.vciclient.nonce

import com.google.gson.annotations.SerializedName
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.Constants.ACCEPT
import io.mosip.vciclient.constants.Constants.APPLICATION_JSON
import io.mosip.vciclient.constants.Constants.CONTENT_TYPE
import io.mosip.vciclient.constants.Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS
import io.mosip.vciclient.constants.Constants.DPOP_NONCE_HEADER
import io.mosip.vciclient.dpop.DPoPManager
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.networkManager.NetworkManager
import io.mosip.vciclient.token.TokenResponse
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

class NonceService(
    private val session: NetworkManager = NetworkManager
) {
    companion object {
        fun extractNonceFromTokenResponse(tokenResponse: TokenResponse): String? {
            val cNonce = tokenResponse.cNonce
            if (!cNonce.isNullOrEmpty()) {
                return cNonce
            }
            return null
        }
    }

    suspend fun fetchNonce(
        issuerMetadata: IssuerMetadata,
        timeoutInMillis: Long = DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        dpopManager: DPoPManager? = null,
        ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    ): String? {
        val nonceEndpoint = issuerMetadata.nonceEndpoint
        if (nonceEndpoint.isNullOrEmpty()) {
            return null
        }

        val request = Request.Builder()
            .url(nonceEndpoint)
            .addHeader(ACCEPT, APPLICATION_JSON)
            .addHeader(CONTENT_TYPE, APPLICATION_JSON)
            .post("{}".toRequestBody(APPLICATION_JSON.toMediaType()))
            .build()

        val response = withContext(ioDispatcher) {
            session.sendRequest(
                request = request,
                timeoutMillis = timeoutInMillis
            )
        }

        dpopManager?.updateNonce(response.headers?.get(DPOP_NONCE_HEADER))

        val nonceResponse = JsonUtils.deserialize(response.body, NonceResponse::class.java)
            ?: throw DownloadFailedException("Failed to parse nonce response.")
        val cNonce = nonceResponse.cNonce
        if (cNonce.isNullOrEmpty()) {
            throw DownloadFailedException("Failed to parse nonce response.")
        }

        return cNonce
    }
}

private data class NonceResponse(
    @SerializedName("c_nonce")
    val cNonce: String? = null,
)
