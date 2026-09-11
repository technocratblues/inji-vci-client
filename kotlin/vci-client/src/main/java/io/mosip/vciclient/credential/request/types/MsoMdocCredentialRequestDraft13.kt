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

class MsoMdocCredentialRequestDraft13(
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
        if (issuerMetadata.doctype.isNullOrEmpty()) {
            validatorResult.addInvalidField("doctype")
        }
        return validatorResult
    }

    private fun generateRequestBody(): RequestBody {
        val credentialRequestBody = MdocCredentialRequestBody(
            proof = proof,
            format = this.issuerMetadata.credentialFormat.value,
            doctype = issuerMetadata.doctype!!
        ).toJson()
        return credentialRequestBody
            .toRequestBody(APPLICATION_JSON.toMediaTypeOrNull())
    }
}

private data class MdocCredentialRequestBody(
    val format: String,
    val doctype: String,
    val proof: Proof?,
) {
    fun toJson(): String {
        return JsonUtils.serialize(this)
    }
}