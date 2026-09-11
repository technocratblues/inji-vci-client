package io.mosip.vciclient.credential.request.types

import com.google.gson.annotations.SerializedName
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

class LdpVcCredentialRequestDraft13(
    override val accessToken: String,
    override val issuerMetadata: IssuerMetadata,
    override val proof: Proof?,
) : CredentialRequest {
    override fun constructRequest(): Request {
        return Request.Builder()
            .url(this.issuerMetadata.credentialEndpoint)
            .addHeader("Authorization", "Bearer ${this.accessToken}")
            .addHeader(CONTENT_TYPE, APPLICATION_JSON)
            .post(generateRequestBody())
            .build()
    }

    override fun validateIssuerMetaData(): ValidatorResult {
        val validatorResult = ValidatorResult()
        if(issuerMetadata.credentialType.isNullOrEmpty()){
            validatorResult.addInvalidField("credentialType")
        }
        return validatorResult
    }

    private fun generateRequestBody(): RequestBody {
        val credentialRequestBody = LdpVcCredentialRequestBody(
            credentialDefinition = CredentialDefinition(type = this.issuerMetadata.credentialType!!, context = this.getCredentialRequestContext()),
            proof = proof,
            format = this.issuerMetadata.credentialFormat.value
        ).toJson()
        return credentialRequestBody
            .toRequestBody(APPLICATION_JSON.toMediaTypeOrNull())
    }

    private fun getCredentialRequestContext(): List<String> {
       return this.issuerMetadata.context ?: listOf("https://www.w3.org/2018/credentials/v1")
    }
}

private data class LdpVcCredentialRequestBody(
    val format: String,
    val credentialDefinition: CredentialDefinition,
    val proof: Proof?,
) {
    fun toJson(): String {
        return JsonUtils.serialize(this)
    }
}

private data class CredentialDefinition(
    @SerializedName("@context")
    val context: List<String>,
    val type: List<String>,
)