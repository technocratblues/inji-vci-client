package io.mosip.vciclient.credential.request

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidDataProvidedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.proof.CredentialRequestProofs
import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialRequestFactoryV2Test {
    @Test
    fun `should create v1 request body with credential configuration id and proofs only`() {
        val factory = CredentialRequestFactory()
        val issuer = IssuerMetadata(
            credentialIssuer = "https://issuer.example.com",
            credentialEndpoint = "https://issuer.example.com/credential",
            credentialType = listOf("VerifiableCredential"),
            credentialFormat = CredentialFormat.LDP_VC
        )

        val request = factory.createCredentialRequest(
            accessToken = "token",
            issuer = issuer,
            credentialConfigurationId = "UniversityDegreeCredential",
            proofs = CredentialRequestProofs(proofs = listOf("proof-1"))
        )

        val buffer = Buffer()
        request.body!!.writeTo(buffer)
        val body = buffer.readUtf8()
        val json = JsonUtils.toMap(body)
        @Suppress("UNCHECKED_CAST")
        val proofs = json["proofs"] as Map<String, Any>

        assertEquals("UniversityDegreeCredential", json["credential_configuration_id"])
        assertEquals(listOf("proof-1"), proofs["jwt"])
        assertNull(json["proof"])
        assertFalse(json.containsKey("format"))
        assertFalse(json.containsKey("credential_definition"))
        assertFalse(json.containsKey("doctype"))
        assertFalse(json.containsKey("vct"))
    }

    @Test
    fun `should create same v1 payload shape for mso mdoc`() {
        val factory = CredentialRequestFactory()

        val body = factory.makeRequestBody(
            credentialConfigurationId = "org.iso.18013.5.1.mDL",
            proofs = CredentialRequestProofs(proofs = listOf("proof-1"))
        )

        val json = JsonUtils.toMap(body)
        assertEquals("org.iso.18013.5.1.mDL", json["credential_configuration_id"])
        assertTrue(json.containsKey("proofs"))
        assertFalse(json.containsKey("doctype"))
        assertFalse(json.containsKey("format"))
    }

    @Test
    fun `should reject empty proof collection`() {
        val factory = CredentialRequestFactory()
        val issuer = IssuerMetadata(
            credentialIssuer = "https://issuer.example.com",
            credentialEndpoint = "https://issuer.example.com/credential",
            credentialFormat = CredentialFormat.LDP_VC
        )

        val exception = assertThrows(InvalidDataProvidedException::class.java) {
            factory.createCredentialRequest(
                accessToken = "token",
                issuer = issuer,
                credentialConfigurationId = "UniversityDegreeCredential",
                proofs = CredentialRequestProofs(proofs = emptyList())
            )
        }

        assertTrue(exception.message!!.contains("Proof collection cannot be empty"))
    }

    @Test
    fun `should reject missing credential endpoint when building base request`() {
        val factory = CredentialRequestFactory()
        val issuer = IssuerMetadata(
            credentialIssuer = "https://issuer.example.com",
            credentialEndpoint = "",
            credentialFormat = CredentialFormat.LDP_VC
        )

        val exception = assertThrows(DownloadFailedException::class.java) {
            factory.constructBaseRequest(
                accessToken = "token",
                issuer = issuer
            )
        }

        assertTrue(exception.message!!.contains("Invalid credential endpoint URL"))
    }

    @Test
    fun `should serialize proofs using the configured proof type`() {
        val factory = CredentialRequestFactory()

        val body = factory.makeRequestBody(
            credentialConfigurationId = "UniversityDegreeCredential",
            proofs = CredentialRequestProofs(
                proofType = "ldp_vp",
                proofs = listOf("proof-1", "proof-2")
            )
        )

        val json = JsonUtils.toMap(body)
        @Suppress("UNCHECKED_CAST")
        val proofs = json["proofs"] as Map<String, Any>

        assertEquals(listOf("proof-1", "proof-2"), proofs["ldp_vp"])
        assertFalse(proofs.containsKey("jwt"))
    }

    @Test
    fun `should omit proofs from request body when proofs are null`() {
        val factory = CredentialRequestFactory()
        val issuer = IssuerMetadata(
            credentialIssuer = "https://issuer.example.com",
            credentialEndpoint = "https://issuer.example.com/credential",
            credentialFormat = CredentialFormat.LDP_VC
        )

        val request = factory.createCredentialRequest(
            accessToken = "token",
            issuer = issuer,
            credentialConfigurationId = "UniversityDegreeCredential",
            proofs = null
        )

        val buffer = Buffer()
        request.body?.writeTo(buffer)
        val json = JsonUtils.toMap(buffer.readUtf8())

        assertEquals("UniversityDegreeCredential", json["credential_configuration_id"])
        assertFalse(json.containsKey("proofs"))
        assertFalse(json.containsKey("proof"))
    }
}
