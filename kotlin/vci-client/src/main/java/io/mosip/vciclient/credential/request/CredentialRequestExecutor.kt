package io.mosip.vciclient.credential.request

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.credential.response.CredentialResponseDraft13
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.dpop.DPoPManager
import io.mosip.vciclient.dpop.WwwAuthenticateChallenge
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidPublicKeyException
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.NetworkRequestTimeoutException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.networkManager.NetworkManager
import io.mosip.vciclient.networkManager.NetworkResponse
import io.mosip.vciclient.proof.Proof
import io.mosip.vciclient.proof.CredentialRequestProofs
import okhttp3.Request
import java.util.logging.Logger

private const val HTTP_UNAUTHORIZED = 401

class CredentialRequestExecutor(
    private val factoryDraft13: CredentialRequestFactoryDraft13 = CredentialRequestFactoryDraft13(),
    private val factory: CredentialRequestFactory = CredentialRequestFactory(),
    private val sendRequest: (Request, Long) -> NetworkResponse =
        { request, timeout -> NetworkManager.sendRequest(request, timeout) },
) {

    private val logTag = Util.getLogTag(javaClass.simpleName, "")
    private val logger = Logger.getLogger(logTag)

    @Throws(
        DownloadFailedException::class,
    )
    fun requestCredential(
        issuerMetadata: IssuerMetadata,
        credentialConfigurationId: String,
        proofs: CredentialRequestProofs?,
        accessToken: String,
        downloadTimeoutInMillis: Long? = 10000,
        tokenType: String? = null,
        dpopManager: DPoPManager = DPoPManager(),
    ): CredentialResponse? {
        val timeout = downloadTimeoutInMillis ?: 10000

        try {
            val request = factory.createCredentialRequest(
                accessToken,
                issuerMetadata,
                credentialConfigurationId,
                proofs
            )

            val networkResponse = sendCredentialRequest(
                baseRequest = request,
                accessToken = accessToken,
                credentialEndpoint = issuerMetadata.credentialEndpoint,
                tokenType = tokenType,
                dpopManager = dpopManager,
                timeoutMillis = timeout
            )

            val responseBody = networkResponse.body

            logger.info("Credential downloaded successfully")

            if (responseBody.isNotBlank()) {
                val credentialResponse =
                    JsonUtils.deserialize(responseBody, CredentialResponse::class.java)
                        ?: throw DownloadFailedException("Failed to parse credential response.")

                credentialResponse.credentials?.forEachIndexed { index, item ->
                    if (item == null) {
                        throw DownloadFailedException("Invalid credential response: credentials[$index] is null.")
                    }
                    if (item.credential == null || item.credential.isJsonNull) {
                        throw DownloadFailedException("Invalid credential response: credentials[$index] is missing the 'credential' key or has a null value.")
                    }
                }

                credentialResponse.credentialConfigurationId = credentialConfigurationId
                credentialResponse.credentialIssuer = issuerMetadata.credentialIssuer

                return credentialResponse
            }

            logger.warning("Credential endpoint returned empty body")
            return null

        } catch (e: NetworkRequestTimeoutException) {
            logger.severe("Credential download timed out after ${timeout / 1000}s")
            throw DownloadFailedException(
                message = "Credential download timed out after ${timeout / 1000}s",
                cause = e,
            )
        } catch (e: NetworkRequestFailedException) {
            logger.severe("Credential download failed: ${e.message}")
            throw DownloadFailedException(
                message = e.message,
                cause = e,
                issuerErrorCode = e.issuerErrorCode,
                issuerErrorDescription = e.issuerErrorDescription
            )
        } catch (e: InvalidPublicKeyException) {
            throw DownloadFailedException(
                e.message,
                cause = e
            )
        } catch (e: DownloadFailedException) {
            throw e
        } catch (e: Exception) {
            logger.severe("Unexpected error during credential download: ${e.message}")
            throw DownloadFailedException(
                message = e.message,
                cause = e
            )
        }
    }

    fun requestCredentialDraft13(
        issuerMetadata: IssuerMetadata,
        credentialConfigurationId: String,
        proof: Proof?,
        accessToken: String,
        downloadTimeoutInMillis: Long? = 10000,
        tokenType: String? = null,
        dpopManager: DPoPManager = DPoPManager(),
    ): CredentialResponseDraft13? {

        val timeout = downloadTimeoutInMillis ?: 10000

        try {

            val request = factoryDraft13.createCredentialRequest(
                issuerMetadata.credentialFormat,
                accessToken,
                issuerMetadata,
                proof
            )

            val networkResponse = sendCredentialRequest(
                baseRequest = request,
                accessToken = accessToken,
                credentialEndpoint = issuerMetadata.credentialEndpoint,
                tokenType = tokenType,
                dpopManager = dpopManager,
                timeoutMillis = timeout
            )

            val responseBody = networkResponse.body

            logger.info("Credential downloaded successfully")

            if (responseBody.isNotBlank()) {

                val credentialResponse =
                    JsonUtils.deserialize(responseBody, CredentialResponseDraft13::class.java)

                credentialResponse?.credentialConfigurationId = credentialConfigurationId
                credentialResponse?.credentialIssuer = issuerMetadata.credentialIssuer

                return credentialResponse
            }

            logger.warning("Credential endpoint returned empty body")
            return null

        } catch (e: NetworkRequestTimeoutException) {
            logger.severe("Credential download timed out after ${timeout / 1000}s")
            throw DownloadFailedException(
                message = "Credential download timed out after ${timeout / 1000}s",
                cause = e,
            )
        } catch (e: NetworkRequestFailedException) {
            logger.severe("Credential download failed: ${e.message}")
            throw DownloadFailedException(
                message = e.message,
                cause = e,
                issuerErrorCode = e.issuerErrorCode,
                issuerErrorDescription = e.issuerErrorDescription
            )
        } catch (e: InvalidPublicKeyException) {
            throw DownloadFailedException(
                e.message,
                cause = e
            )
        } catch (e: Exception) {
            logger.severe("Unexpected error during credential download: ${e.message}")
            throw DownloadFailedException(
                message = e.message,
                cause = e
            )
        }
    }

    /**
     * Sends the credential request, applying DPoP when the token response carried
     * `token_type=DPoP`. A `use_dpop_nonce` challenge is retried once with the server supplied
     * nonce; a Bearer-only challenge triggers a best-effort Bearer retry per RFC 9449 section 7.2.
     */
    private fun sendCredentialRequest(
        baseRequest: Request,
        accessToken: String,
        credentialEndpoint: String,
        tokenType: String?,
        dpopManager: DPoPManager,
        timeoutMillis: Long,
    ): NetworkResponse {
        val isDpopToken = tokenType.equals(Constants.DPOP_TOKEN_TYPE, ignoreCase = true)
        if (isDpopToken && !dpopManager.isInitialized) {
            throw DownloadFailedException("DPoP token_type requires an initialized DPoP session")
        }
        if (!isDpopToken) {
            return sendRequest(baseRequest, timeoutMillis)
        }

        val dpopRequest = withDpop(
            baseRequest,
            accessToken,
            dpopManager.generateCredentialProof(credentialEndpoint, accessToken)
        )

        return try {
            sendRequest(dpopRequest, timeoutMillis).persistIssuerNonce(dpopManager)
        } catch (failure: NetworkRequestFailedException) {
            if (failure.httpStatusCode != HTTP_UNAUTHORIZED) throw failure

            val challenge = WwwAuthenticateChallenge.parse(
                failure.headers?.values(Constants.WWW_AUTHENTICATE_HEADER)?.joinToString(", ")
            )
            val nonce = failure.headers?.get(Constants.DPOP_NONCE_HEADER)

            when {
                challenge.error == Constants.USE_DPOP_NONCE_ERROR && nonce != null -> {
                    sendRequest(
                        withDpop(
                            baseRequest,
                            accessToken,
                            dpopManager.generateCredentialProof(credentialEndpoint, accessToken, nonce)
                        ),
                        timeoutMillis
                    ).persistIssuerNonce(dpopManager)
                }

                !challenge.isDpop && challenge.isBearer -> {
                    // RFC 9449 §7.2: Only downgrade to Bearer if the AS explicitly
                    // signals Bearer is acceptable. Log as a security-relevant event.
                    logger.warning(
                        "DPoP token downgraded to Bearer: AS does not require DPoP " +
                        "(WWW-Authenticate: ${failure.headers?.get(Constants.WWW_AUTHENTICATE_HEADER)})"
                    )
                    sendRequest(withBearer(baseRequest, accessToken), timeoutMillis)
                }

                else -> throw failure
            }
        }
    }

    private fun NetworkResponse.persistIssuerNonce(dpopManager: DPoPManager): NetworkResponse =
        also { dpopManager.updateNonce(it.headers?.get(Constants.DPOP_NONCE_HEADER)) }

    private fun withDpop(baseRequest: Request, accessToken: String, proof: String): Request =
        baseRequest.newBuilder()
            .header(Constants.AUTHORIZATION_HEADER, "${Constants.DPOP_TOKEN_TYPE} $accessToken")
            .header(Constants.DPOP_HEADER, proof)
            .build()

    private fun withBearer(baseRequest: Request, accessToken: String): Request =
        baseRequest.newBuilder()
            .header(Constants.AUTHORIZATION_HEADER, "${Constants.BEARER_TOKEN_TYPE} $accessToken")
            .removeHeader(Constants.DPOP_HEADER)
            .build()

}
