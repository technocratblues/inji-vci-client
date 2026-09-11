package io.mosip.vciclient.credential.request

import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.exception.InvalidDataProvidedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.credential.request.types.LdpVcCredentialRequestDraft13
import io.mosip.vciclient.credential.request.types.MsoMdocCredentialRequestDraft13
import io.mosip.vciclient.credential.request.types.SdJwtCredentialRequestDraft13
import io.mosip.vciclient.proof.Proof
import io.mosip.vciclient.proof.jwt.JWTProof
import okhttp3.Request

class CredentialRequestFactoryDraft13 {
    fun createCredentialRequest(
        credentialFormat: CredentialFormat,
        accessToken: String,
        issuerMetadata: IssuerMetadata,
        proof: Proof?,
    ): Request {
        val jwtProof = if (proof != null) {
        val validatedProof = proof as? JWTProof
            ?: throw InvalidDataProvidedException("Proof object cannot be empty or invalid")
        if (validatedProof.jwt.isEmpty()) {
            throw InvalidDataProvidedException("Proof object cannot be empty or invalid")
        }
            validatedProof
        } else {
            null
        }

        val credentialRequest = when (credentialFormat) {
            CredentialFormat.LDP_VC -> LdpVcCredentialRequestDraft13(accessToken, issuerMetadata, jwtProof)
            CredentialFormat.MSO_MDOC -> MsoMdocCredentialRequestDraft13(accessToken, issuerMetadata, jwtProof)
            CredentialFormat.VC_SD_JWT, CredentialFormat.DC_SD_JWT -> {
                SdJwtCredentialRequestDraft13(accessToken, issuerMetadata, jwtProof)
            }
        }

        return validateAndConstructCredentialRequest(credentialRequest)
    }

    fun validateAndConstructCredentialRequest(credentialRequest: CredentialRequest): Request {
        val issuerMetadataValidatorResult = credentialRequest.validateIssuerMetaData()
        if (issuerMetadataValidatorResult.isValid) {
            return credentialRequest.constructRequest()
        }
        throw InvalidDataProvidedException("invalid fields: ${issuerMetadataValidatorResult.invalidFields.joinToString(", ")}")
    }
}
