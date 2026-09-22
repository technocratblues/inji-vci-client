package io.mosip.vciclient.credentialOffer

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.Constants.APPLICATION_JSON
import io.mosip.vciclient.exception.CredentialOfferFetchFailedException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URI
import java.net.URLDecoder

internal class CredentialOfferService(
     private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
      private val defaultDispatcher: CoroutineDispatcher = Dispatchers.Default
) {

    suspend fun fetchCredentialOffer(credentialOfferData: String): CredentialOffer {
        try {
            val normalized = credentialOfferData.replace(
                "openid-credential-offer://?", "openid-credential-offer://dummy?"
            )
            val uri = URI(normalized)
            val queryParams = uri.rawQuery?.split("&")?.associate {
                val (key, value) = it.split("=")
                key to URLDecoder.decode(value, "UTF-8")
            } ?: throw CredentialOfferFetchFailedException("No query parameters in the URI")

            return when {
                queryParams.containsKey("credential_offer") -> {
                    val offer = queryParams["credential_offer"]
                        ?: throw CredentialOfferFetchFailedException("'credential_offer' in query parameters has empty value")
                    handleByValueOffer(offer)
                }

                queryParams.containsKey("credential_offer_uri") -> {
                    val uriOffer = queryParams["credential_offer_uri"]
                        ?: throw CredentialOfferFetchFailedException("'credential_offer_uri' in query parameters has empty value")
                    handleByReferenceOffer(uriOffer)
                }

                else -> throw CredentialOfferFetchFailedException(
                    "Invalid credential offer URL: must contain 'credential_offer' or 'credential_offer_uri'"
                )
            }
        } catch (e: CredentialOfferFetchFailedException) {
            throw e
        } catch (e: VCIClientException) {
            throw CredentialOfferFetchFailedException(
                e.message,
                e.issuerErrorCode,
                e.issuerErrorDescription,
                e
            )
        } catch (e: Exception) {
            throw CredentialOfferFetchFailedException(
                message = e.message,
                null,
                null,
                cause = e
            )
        }
    }

    internal fun handleByValueOffer(encodedOffer: String): CredentialOffer {
        val decodedOffer = URLDecoder.decode(encodedOffer, "UTF-8")
        val credentialOffer = (JsonUtils.deserialize(decodedOffer, CredentialOffer::class.java)
            ?: throw CredentialOfferFetchFailedException("Invalid credential offer JSON"))
        CredentialOfferValidator.validate(credentialOffer)
        return credentialOffer
    }

    internal suspend fun handleByReferenceOffer(url: String): CredentialOffer {
        val responseBody = withContext(ioDispatcher) {
            val response = NetworkManager.sendRequest(
                url = url, method = HttpMethod.GET, headers = mapOf("Accept" to APPLICATION_JSON)
            )

            if (response.body.isBlank()) {
                throw CredentialOfferFetchFailedException("Empty response from $url")
            }

            response.body
        }

        val credentialOffer = withContext(defaultDispatcher) {
            JsonUtils.deserialize(responseBody, CredentialOffer::class.java)
                ?: throw CredentialOfferFetchFailedException("Invalid credential offer JSON")
        }

        CredentialOfferValidator.validate(credentialOffer)
        return credentialOffer
    }

}