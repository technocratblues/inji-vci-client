package io.mosip.vciclient.proof

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProofBindingContextTest {
    @Test
    fun `requiresProof should be true when binding methods and proof types are present`() {
        val context = ProofBindingContext(
            cryptographicBindingMethodsSupported = listOf("did:jwk"),
            proofTypesSupported = listOf("jwt"),
        )

        assertTrue(context.requiresProof)
    }

    @Test
    fun `requiresProof should be false when binding methods are absent`() {
        val context = ProofBindingContext(proofTypesSupported = listOf("jwt"))

        assertFalse(context.requiresProof)
    }

    @Test
    fun `requiresProof should be false when proof types are absent`() {
        val context = ProofBindingContext(cryptographicBindingMethodsSupported = listOf("did:jwk"))

        assertFalse(context.requiresProof)
    }

    @Test
    fun `requiresProof should be false when neither is present`() {
        assertFalse(ProofBindingContext(proofSigningAlgorithmsSupported = listOf("ES256")).requiresProof)
    }
}
