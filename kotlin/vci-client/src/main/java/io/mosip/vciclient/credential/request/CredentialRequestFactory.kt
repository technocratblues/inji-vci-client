package io.mosip.vciclient.credential.request

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.Constants.APPLICATION_JSON
import io.mosip.vciclient.constants.Constants.CONTENT_TYPE
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidDataProvidedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.proof.CredentialRequestProofs
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

class CredentialRequestFactory {
    fun createCredentialRequest(
        accessToken: String,
        issuer: IssuerMetadata,
        credentialConfigurationId: String,
        proofs: CredentialRequestProofs?,
    ): Request {
        if (proofs != null && proofs.isEmpty) {
            throw InvalidDataProvidedException("Proof collection cannot be empty")
        }

        val requestBody = makeRequestBody(
            credentialConfigurationId = credentialConfigurationId,
            proofs = proofs
        )

        return constructBaseRequest(accessToken, issuer)
            .post(requestBody.toRequestBody(APPLICATION_JSON.toMediaTypeOrNull()))
            .build()
    }

    fun constructBaseRequest(
        accessToken: String,
        issuer: IssuerMetadata,
    ): Request.Builder {
        if (issuer.credentialEndpoint.isEmpty()) {
            throw DownloadFailedException("Invalid credential endpoint URL")
        }

        return Request.Builder()
            .url(issuer.credentialEndpoint)
            .addHeader("Authorization", "Bearer $accessToken")
            .addHeader(CONTENT_TYPE, APPLICATION_JSON)
    }

    fun makeRequestBody(
        credentialConfigurationId: String,
        proofs: CredentialRequestProofs?,
    ): String {
        return JsonUtils.serialize(
            CredentialRequestBody(
                credentialConfigurationId = credentialConfigurationId,
                proofs = proofs
            )
        )
    }
}

private data class CredentialRequestBody(
    val credentialConfigurationId: String,
    val proofs: CredentialRequestProofs?,
)
