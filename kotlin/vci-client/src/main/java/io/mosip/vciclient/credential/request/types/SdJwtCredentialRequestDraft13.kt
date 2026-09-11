package io.mosip.vciclient.credential.request.types

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.Constants.APPLICATION_JSON
import io.mosip.vciclient.constants.Constants.CONTENT_TYPE
import io.mosip.vciclient.credential.request.CredentialRequest
import io.mosip.vciclient.credential.request.util.ValidatorResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.proof.Proof
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody

class SdJwtCredentialRequestDraft13(
    override val accessToken: String,
    override val issuerMetadata: IssuerMetadata,
    override val proof: Proof?,
) : CredentialRequest {

    override fun constructRequest(): Request {
        return Request.Builder()
            .url(issuerMetadata.credentialEndpoint)
            .addHeader("Authorization", "Bearer $accessToken")
            .addHeader(CONTENT_TYPE, APPLICATION_JSON)
            .post(generateRequestBody())
            .build()
    }

    override fun validateIssuerMetaData(): ValidatorResult {
        val validatorResult = ValidatorResult()
        if (issuerMetadata.vct.isNullOrEmpty()) {
            validatorResult.addInvalidField("vct")
        }
        return validatorResult
    }

    private fun generateRequestBody(): RequestBody {
        val request = SdJwtRequestBody(
            format = issuerMetadata.credentialFormat.value,
            vct = issuerMetadata.vct!!,
            proof = proof,
            claims = issuerMetadata.claims
        ).toJson()

        return request.toRequestBody(APPLICATION_JSON.toMediaTypeOrNull())
    }
}

private data class SdJwtRequestBody(
    val format: String,
    val vct: String,
    val proof: Proof?,
    val claims: Map<String, Any>? = null
) {
    fun toJson(): String = JsonUtils.serialize(this)
}
