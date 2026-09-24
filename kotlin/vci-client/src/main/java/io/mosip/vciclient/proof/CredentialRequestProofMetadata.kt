package io.mosip.vciclient.proof

import io.mosip.vciclient.issuerMetadata.IssuerMetadataResult


data class CredentialRequestProofMetadata(
    val credentialIssuer: String,
    val nonce: String?,
    val proofSigningAlgorithmsSupported: List<String> = emptyList(),
    val cryptographicBindingMethodsSupported: List<String> = emptyList(),
    val proofTypesSupported: List<String> = emptyList(),
)


internal data class ProofBindingContext(
    val proofSigningAlgorithmsSupported: List<String> = emptyList(),
    val cryptographicBindingMethodsSupported: List<String> = emptyList(),
    val proofTypesSupported: List<String> = emptyList(),
) {
    val requiresProof: Boolean
        get() = cryptographicBindingMethodsSupported.isNotEmpty() && proofTypesSupported.isNotEmpty()
    fun toCredentialRequestProofMetadata(credentialIssuer: String, nonce: String?): CredentialRequestProofMetadata = CredentialRequestProofMetadata(
        credentialIssuer = credentialIssuer,
        nonce = nonce,
        proofSigningAlgorithmsSupported = proofSigningAlgorithmsSupported,
        cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported,
        proofTypesSupported = proofTypesSupported,
    )
}

internal fun IssuerMetadataResult.toProofBindingContext(
    credentialConfigurationId: String,
): ProofBindingContext = ProofBindingContext(
    proofSigningAlgorithmsSupported = extractJwtProofSigningAlgorithms(credentialConfigurationId),
    cryptographicBindingMethodsSupported = extractCryptographicBindingMethods(credentialConfigurationId),
    proofTypesSupported = extractSupportedProofTypes(credentialConfigurationId),
)
