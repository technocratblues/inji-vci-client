package io.mosip.vciclient.issuerMetadata

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.common.WellKnownUrl
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.constants.OID4VCIVersion
import io.mosip.vciclient.exception.IssuerMetadataFetchException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val CREDENTIAL_ISSUER_WELL_KNOWN_URI_SUFFIX = "/.well-known/openid-credential-issuer"

@Suppress("UNCHECKED_CAST")
class IssuerMetadataService (
      private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) {
    private val timeoutMillis: Long = 10000
    private val cachedRawMetadata: MutableMap<String, Map<String, Any>> = mutableMapOf()

    /**
     * Fetches and resolves issuer metadata for a given issuer URI and credential configuration ID.
     * Stores the result in a cache (member property) to avoid redundant network calls.
     */
    suspend fun fetchIssuerMetadataResult(
        credentialIssuer: String,
        credentialConfigurationId: String
    ): IssuerMetadataResult = withContext(ioDispatcher) {
        try {
            val rawIssuerMetadata = getOrFetchCachedMetadata(credentialIssuer)

            validateCredentialIssuerMatch(
                expected = credentialIssuer,
                rawMetadata = rawIssuerMetadata
            )

            val resolvedIssuerMetadata = resolveMetadata(
                credentialConfigurationId = credentialConfigurationId,
                rawIssuerMetadata = rawIssuerMetadata
            )

            return@withContext IssuerMetadataResult(
                issuerMetadata = resolvedIssuerMetadata,
                raw = rawIssuerMetadata,
                credentialIssuer = credentialIssuer
            )
        } catch (e: IssuerMetadataFetchException) {
            throw e
        } catch (e: VCIClientException) {
            throw IssuerMetadataFetchException(
                e.message,
                issuerErrorCode = e.issuerErrorCode,
                issuerErrorDescription = e.issuerErrorDescription,
                cause = e
            )
        } catch (e: Exception) {
            throw IssuerMetadataFetchException(
                "Unexpected error while resolving issuer metadata: ${e.message}",
                cause = e
            )
        }
    }

    suspend fun fetchCredentialConfigurationsSupported(credentialIssuer: String): Map<String, Any> {
        val rawIssuerMetadata = fetchAndParseIssuerMetadata(credentialIssuer)

        validateCredentialIssuerMatch(
            expected = credentialIssuer,
            rawMetadata = rawIssuerMetadata
        )

        val configurations = rawIssuerMetadata["credential_configurations_supported"] as? Map<*, *>
            ?: throw IssuerMetadataFetchException("Missing or invalid 'credential_configurations_supported' in issuer metadata.")

        if (configurations.isEmpty()) {
            throw IssuerMetadataFetchException("'credential_configurations_supported' is empty.")
        }

        configurations.forEach { (configId, config) ->
            val configMap = config as? Map<*, *>
                ?: throw IssuerMetadataFetchException("Invalid configuration format for '$configId'")

            if (configMap["format"] == null) {
                throw IssuerMetadataFetchException("Missing 'format' in configuration '$configId'")
            }
        }

        return configurations as Map<String, Any>
    }

    suspend fun fetchAndParseIssuerMetadata(credentialIssuer: String): Map<String, Any> =
        withContext(ioDispatcher) {
            val wellKnownUrl: String
            val draft13WellKnownUrl: String
            try {
                wellKnownUrl = buildWellKnownUrl(credentialIssuer)
                draft13WellKnownUrl = buildDraft13WellKnownUrl(credentialIssuer)
            } catch (e: Exception) {
                throw IssuerMetadataFetchException(
                    "Invalid credential issuer URL: $credentialIssuer",
                    cause = e
                )
            }

            try {
                fetchAndParse(wellKnownUrl)
            } catch (error: IssuerMetadataFetchException) {
                if (draft13WellKnownUrl == wellKnownUrl) throw error
                fetchAndParse(draft13WellKnownUrl)
            }
        }

    private fun fetchAndParse(wellKnownUrl: String): Map<String, Any> {
        try {
            val response = NetworkManager.sendRequest(
                url = wellKnownUrl,
                method = HttpMethod.GET,
                timeoutMillis = timeoutMillis
            )

            val body = response.body
            if (body.isBlank()) {
                throw IssuerMetadataFetchException("Issuer metadata response is empty.")
            }
            return JsonUtils.toMap(body)
        } catch (e: IssuerMetadataFetchException) {
            throw e
        } catch (e: VCIClientException) {
            throw IssuerMetadataFetchException(
                e.message,
                issuerErrorCode = e.issuerErrorCode,
                issuerErrorDescription = e.issuerErrorDescription,
                cause = e
            )
        } catch (e: Exception) {
            throw IssuerMetadataFetchException(
                "Unexpected error while fetching issuer metadata: ${e.message}",
                cause = e
            )
        }
    }

    private fun buildWellKnownUrl(credentialIssuer: String): String =
        WellKnownUrl.insertSuffix(credentialIssuer, CREDENTIAL_ISSUER_WELL_KNOWN_URI_SUFFIX)

    private fun buildDraft13WellKnownUrl(credentialIssuer: String): String {
        val normalizedIssuer = credentialIssuer.trimEnd('/')
        return "$normalizedIssuer$CREDENTIAL_ISSUER_WELL_KNOWN_URI_SUFFIX"
    }

    private fun validateCredentialIssuerMatch(
        expected: String,
        rawMetadata: Map<String, Any>
    ) {
        val actual = rawMetadata["credential_issuer"] as? String
            ?: throw IssuerMetadataFetchException("Missing credential_issuer in issuer metadata")
        if (expected != actual) {
            throw IssuerMetadataFetchException(
                "credential_issuer mismatch: expected '$expected', got '$actual'"
            )
        }
    }

    private suspend fun getOrFetchCachedMetadata(credentialIssuer: String) =
        cachedRawMetadata[credentialIssuer] ?: run {
            val fetched = fetchAndParseIssuerMetadata(credentialIssuer)
            cachedRawMetadata[credentialIssuer] = fetched
            fetched
        }

    private fun resolveMetadata(
        credentialConfigurationId: String,
        rawIssuerMetadata: Map<String, Any>
    ): IssuerMetadata {
        val credentialConfigurationsSupported =
            rawIssuerMetadata["credential_configurations_supported"] as? Map<*, *>
                ?: throw IssuerMetadataFetchException("Missing credential_configurations_supported")
        val credentialType =
            credentialConfigurationsSupported[credentialConfigurationId] as? Map<*, *>
                ?: throw IssuerMetadataFetchException("Credential configuration not found: $credentialConfigurationId")
        val credentialEndpoint = rawIssuerMetadata["credential_endpoint"] as? String
            ?: throw IssuerMetadataFetchException("Missing credential_endpoint")
        val credentialIssuer = rawIssuerMetadata["credential_issuer"] as? String
            ?: throw IssuerMetadataFetchException("Missing credential_issuer")
        val format = credentialType["format"] as? String
        val scope = credentialType["scope"] as? String ?: "openid"
        val nonceEndpoint = rawIssuerMetadata["nonce_endpoint"] as? String
        val specVersion = detectSpecVersion(rawIssuerMetadata, credentialType)

        return when (format) {
            CredentialFormat.MSO_MDOC.value -> {
                val doctype = credentialType["doctype"] as? String
                    ?: throw IssuerMetadataFetchException("Missing doctype")
                val claims = credentialType["claims"] as? Map<String, Any>

                IssuerMetadata(
                    credentialIssuer = credentialIssuer,
                    credentialEndpoint = credentialEndpoint,
                    credentialFormat = CredentialFormat.MSO_MDOC,
                    doctype = doctype,
                    claims = claims,
                    scope = scope,
                    authorizationServers = rawIssuerMetadata["authorization_servers"] as? List<String>,
                    nonceEndpoint = nonceEndpoint,
                    specVersion = specVersion
                )
            }

            CredentialFormat.LDP_VC.value -> {
                val credentialDefinition =
                    credentialType["credential_definition"] as? Map<*, *> ?: emptyMap<String, Any>()
                val types = credentialDefinition["type"] as? List<String>
                val context = credentialDefinition["@context"] as? List<String>

                IssuerMetadata(
                    credentialIssuer = credentialIssuer,
                    credentialEndpoint = credentialEndpoint,
                    credentialType = types,
                    context = context,
                    credentialFormat = CredentialFormat.LDP_VC,
                    authorizationServers = rawIssuerMetadata["authorization_servers"] as? List<String>,
                    scope = scope,
                    nonceEndpoint = nonceEndpoint,
                    specVersion = specVersion
                )
            }

            CredentialFormat.VC_SD_JWT.value, CredentialFormat.DC_SD_JWT.value -> {
                val vct = credentialType["vct"] as? String
                    ?: throw IssuerMetadataFetchException("Missing vct for SD-JWT")

                val claims = credentialType["claims"] as? Map<String, Any>
                val resolvedFormat = CredentialFormat.values().firstOrNull { it.value == format }
                    ?: throw IssuerMetadataFetchException("Unrecognized credential format: $format")

                IssuerMetadata(
                    credentialIssuer = credentialIssuer,
                    credentialEndpoint = credentialEndpoint,
                    credentialFormat = resolvedFormat,
                    vct = vct,
                    claims = claims,
                    scope = scope,
                    authorizationServers = rawIssuerMetadata["authorization_servers"] as? List<String>,
                    nonceEndpoint = nonceEndpoint,
                    specVersion = specVersion
                )
            }

            else -> throw IssuerMetadataFetchException("Unsupported or missing credential format in configuration")
        }
    }

    private fun detectSpecVersion(
        rawIssuerMetadata: Map<String, Any>,
        credentialConfiguration: Map<*, *>
    ): OID4VCIVersion {
        val nonceEndpoint = rawIssuerMetadata["nonce_endpoint"] as? String
        if (!nonceEndpoint.isNullOrEmpty()) {
            return OID4VCIVersion.V1
        }

        if (credentialConfiguration["credential_metadata"] != null) {
            return OID4VCIVersion.V1
        }

        if (credentialConfiguration["display"] != null) {
            return OID4VCIVersion.DRAFT13
        }

        return OID4VCIVersion.V1
    }
}
