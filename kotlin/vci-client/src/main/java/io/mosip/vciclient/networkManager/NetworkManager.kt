package io.mosip.vciclient.networkManager

import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.NetworkRequestTimeoutException
import okhttp3.FormBody
import okhttp3.Headers
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.InterruptedIOException
import java.util.concurrent.TimeUnit
import java.util.logging.Logger

private const val ERROR_CODE = "error"
private const val ERROR_DESCRIPTION = "error_description"
private val LOOPBACK_HOSTS = setOf("localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1")

object NetworkManager {

    private val baseClient = OkHttpClient()

    private fun getClient(timeoutMillis: Long): OkHttpClient =
        baseClient.newBuilder()
            .callTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
            .build()

    @Throws(
        NetworkRequestTimeoutException::class,
        NetworkRequestFailedException::class
    )
    fun sendRequest(
        request: Request,
        timeoutMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): NetworkResponse {

        val requestUrl = request.url
        if (!requestUrl.isHttps && requestUrl.host.lowercase() !in LOOPBACK_HOSTS) {
            throw NetworkRequestFailedException(
                message = "Plaintext HTTP endpoints are not allowed; use HTTPS for: $requestUrl"
            )
        }

        try {
            val client = getClient(timeoutMillis)

            client.newCall(request).execute().use { response ->

                val responseBody = response.body?.string().orEmpty()

                if (!response.isSuccessful) {
                    val (issuerErrorCode, issuerErrorDescription) =
                        parseServerErrorResponse(responseBody)

                    throw NetworkRequestFailedException(
                        message = "HTTP ${response.code}",
                        httpStatusCode = response.code,
                        headers = response.headers,
                        issuerErrorCode = issuerErrorCode,
                        issuerErrorDescription = issuerErrorDescription
                    )
                }

                return NetworkResponse(
                    body = responseBody,
                    headers = response.headers
                )
            }

        } catch (e: InterruptedIOException) {
            throw NetworkRequestTimeoutException(
                message = e.message,
                cause = e
            )
        } catch (e: NetworkRequestFailedException) {
            throw e
        } catch (e: Exception) {
            throw NetworkRequestFailedException(
                message = e.message ?: "Unknown error",
                cause = e
            )
        }
    }


    @Throws(
        NetworkRequestTimeoutException::class,
        NetworkRequestFailedException::class
    )
    fun sendRequest(
        url: String,
        method: HttpMethod,
        headers: Map<String, String>? = null,
        bodyParams: Map<String, String>? = null,
        timeoutMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): NetworkResponse {

        val requestBuilder = Request.Builder().url(url)

        headers?.forEach { (key, value) ->
            requestBuilder.addHeader(key, value)
        }

        when (method) {
            HttpMethod.GET -> requestBuilder.get()
            HttpMethod.POST -> {
                val formBodyBuilder = FormBody.Builder()
                bodyParams?.forEach { (key, value) ->
                    formBodyBuilder.add(key, value)
                }
                requestBuilder.post(formBodyBuilder.build())
            }
        }

        return sendRequest(
            request = requestBuilder.build(),
            timeoutMillis = timeoutMillis
        )
    }


    private fun parseServerErrorResponse(responseBody: String): Pair<String?, String?> {
    return try {
        val json = JSONObject(responseBody)

        Pair(
            json.optString(ERROR_CODE),
            json.optString(ERROR_DESCRIPTION)
        )
    } catch (_: Exception) {
        Logger.getLogger(NetworkManager::class.java.name)
            .warning("Failed to parse server error response")

        Pair(null, responseBody)
    }
    }

}

data class NetworkResponse(
    val body: String,
    val headers: Headers?,
)
