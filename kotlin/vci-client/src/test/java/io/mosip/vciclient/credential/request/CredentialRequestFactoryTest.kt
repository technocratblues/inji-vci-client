package io.mosip.vciclient.credential.request

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.exception.InvalidDataProvidedException
import io.mosip.vciclient.proof.Proof
import io.mosip.vciclient.proof.jwt.JWTProof
import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Test

class CredentialRequestFactoryDraft13Test {
    private val ldpVcIssuerMetadata = IssuerMetadata(
        "/credentialAudience",
        "https://credentialendpoint/",
        listOf("VerifiableCredential"),
        credentialFormat = CredentialFormat.LDP_VC,
    )

    @Test
    fun `should throw exception when required details are not available in Issuer metadata based on VC format`() {
        val factory = CredentialRequestFactoryDraft13()

        assertThrows(
            InvalidDataProvidedException::class.java,
        ) {
            factory.createCredentialRequest(
                CredentialFormat.MSO_MDOC, "access-token",
                IssuerMetadata(
                    "/credentialAudience",
                    "https://credentialendpoint/",
                    credentialFormat = CredentialFormat.LDP_VC,
                ), JWTProof("headerEncoded.payloadEncoded.signature")
            )
        }
        assertThrows(
            InvalidDataProvidedException::class.java,
        ) {
            factory.createCredentialRequest(
                CredentialFormat.MSO_MDOC, "access-token",
                IssuerMetadata(
                    "/credentialAudience",
                    "https://credentialendpoint/",
                    listOf("Uni"),
                    credentialFormat = CredentialFormat.MSO_MDOC,
                    claims = mapOf("org.iso.18013.5.1" to mapOf("given_name" to emptyMap<String, Any>())),
                ), JWTProof("headerEncoded.payloadEncoded.signature")
            )
        }
        assertThrows(
            InvalidDataProvidedException::class.java,
        ) {
            factory.createCredentialRequest(
                CredentialFormat.VC_SD_JWT, "access-token",
                IssuerMetadata(
                    "/credentialAudience",
                    "https://credentialendpoint/",
                    credentialFormat = CredentialFormat.VC_SD_JWT,
                    claims = mapOf("name" to "Alice") // vct missing
                ), JWTProof("headerEncoded.payloadEncoded.signature")
            )
        }
    }

    @Test
    fun `should omit proof from request body when proof is null`() {
        val request = CredentialRequestFactoryDraft13().createCredentialRequest(
            CredentialFormat.LDP_VC, "access-token", ldpVcIssuerMetadata, null
        )

        val buffer = Buffer()
        request.body?.writeTo(buffer)
        val json = JsonUtils.toMap(buffer.readUtf8())

        assertEquals("ldp_vc", json["format"])
        assertNotNull(json["credential_definition"])
        assertFalse(json.containsKey("proof"))
    }

    @Test
    fun `should reject proof with empty jwt`() {
        assertThrows(InvalidDataProvidedException::class.java) {
            CredentialRequestFactoryDraft13().createCredentialRequest(
                CredentialFormat.LDP_VC, "access-token", ldpVcIssuerMetadata, JWTProof("")
            )
        }
    }

    @Test
    fun `should reject proof that is not a jwt proof`() {
        val ldpVpProof = object : Proof {
            override val proofType: String = "ldp_vp"
        }

        assertThrows(InvalidDataProvidedException::class.java) {
            CredentialRequestFactoryDraft13().createCredentialRequest(
                CredentialFormat.LDP_VC, "access-token", ldpVcIssuerMetadata, ldpVpProof
            )
        }
    }

}
