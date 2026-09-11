package io.mosip.vciclient.issuerMetadata

data class IssuerMetadataResult(
    var issuerMetadata: IssuerMetadata,
    val raw: Map<String, Any?>,
    val credentialIssuer: String? = null
) {
    fun extractJwtProofSigningAlgorithms(credentialConfigurationId: String): List<String> {
        val jwt = proofTypesSupported(credentialConfigurationId)?.get("jwt") as? Map<*, *>
        val jwtProofSigningAlgorithmsSupported = jwt?.get("proof_signing_alg_values_supported") as? List<*>

        return jwtProofSigningAlgorithmsSupported?.filterIsInstance<String>() ?: emptyList()
    }

    fun extractSupportedProofTypes(credentialConfigurationId: String): List<String> {
        val proofTypes = proofTypesSupported(credentialConfigurationId) ?: return emptyList()

        return proofTypes.keys.filterIsInstance<String>()
    }

    fun extractCryptographicBindingMethods(credentialConfigurationId: String): List<String> {
        val config = credentialConfiguration(credentialConfigurationId)
        val bindingMethods = config?.get("cryptographic_binding_methods_supported") as? List<*>

        return bindingMethods?.filterIsInstance<String>() ?: emptyList()
    }

    fun isHolderBindingRequired(credentialConfigurationId: String): Boolean {
        return extractCryptographicBindingMethods(credentialConfigurationId).isNotEmpty() &&
                extractSupportedProofTypes(credentialConfigurationId).isNotEmpty()
    }

    private fun credentialConfiguration(credentialConfigurationId: String): Map<*, *>? {
        val configurations = this.raw["credential_configurations_supported"] as? Map<*, *>

        return configurations?.get(credentialConfigurationId) as? Map<*, *>
    }

    private fun proofTypesSupported(credentialConfigurationId: String): Map<*, *>? {
        return credentialConfiguration(credentialConfigurationId)?.get("proof_types_supported") as? Map<*, *>
    }
}