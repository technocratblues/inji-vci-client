package io.mosip.vciclient.nonce

import com.nimbusds.jwt.SignedJWT
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.dpop.DPoPManager
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.token.TokenResponse
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.net.InetAddress
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class NonceServiceTest {
    private lateinit var server: MockWebServer

    private fun MockWebServer.localUrl(path: String) =
        url(path).newBuilder().host("127.0.0.1").build()

    private lateinit var nonceService: NonceService

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start(InetAddress.getByName("127.0.0.1"), 0)
        nonceService = NonceService()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `fetchNonce should return null when issuer does not expose nonce endpoint`() = runBlocking {
        val issuerMetadata = issuerMetadata(nonceEndpoint = null)

        val nonce = nonceService.fetchNonce(issuerMetadata)

        assertNull(nonce)
    }

    @Test
    fun `fetchNonce should post json and return c nonce from response body`() = runBlocking {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"c_nonce":"nonce-123"}""")
        )

        val nonce = nonceService.fetchNonce(
            issuerMetadata = issuerMetadata(
                nonceEndpoint = server.localUrl("/nonce").toString()
            )
        )

        val recordedRequest = server.takeRequest()

        assertEquals("nonce-123", nonce)
        assertEquals("POST", recordedRequest.method)
        assertEquals("application/json", recordedRequest.getHeader("Accept"))
        assertTrue(recordedRequest.getHeader("Content-Type")!!.startsWith("application/json"))
        assertEquals("{}", recordedRequest.body.readUtf8())
    }

    @Test
    fun `fetchNonce should fail when response body does not contain c nonce`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"expires_in":30}""")
        )

        val exception = assertThrows(DownloadFailedException::class.java) {
            runBlocking {
                nonceService.fetchNonce(
                    issuerMetadata = issuerMetadata(
                        nonceEndpoint = server.localUrl("/nonce").toString()
                    )
                )
            }
        }

        assertEquals(
            "Failed to download Credential: Failed to parse nonce response.",
            exception.message
        )
    }

    @Test
    fun `fetchNonce should seed dpop nonce from DPoP-Nonce response header`() = runBlocking {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setHeader("DPoP-Nonce", "dpop-nonce-xyz")
                .setBody("""{"c_nonce":"nonce-123"}""")
        )
        val dpopManager = DPoPManager().apply {
            initialize("https://as.example.com/token", listOf("ES256"))
        }

        val nonce = nonceService.fetchNonce(
            issuerMetadata = issuerMetadata(nonceEndpoint = server.localUrl("/nonce").toString()),
            dpopManager = dpopManager
        )

        assertEquals("nonce-123", nonce)
        val claims = SignedJWT.parse(
            dpopManager.generateCredentialProof(
                credentialEndpoint = "https://issuer.example.com/credential",
                accessToken = "an-access-token"
            )
        ).jwtClaimsSet
        assertEquals("dpop-nonce-xyz", claims.getStringClaim("nonce"))
    }

    @Test
    fun `fetchNonce should leave dpop nonce untouched when header is absent`() = runBlocking {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"c_nonce":"nonce-123"}""")
        )
        val dpopManager = DPoPManager().apply {
            initialize("https://as.example.com/token", listOf("ES256"))
        }

        nonceService.fetchNonce(
            issuerMetadata = issuerMetadata(nonceEndpoint = server.localUrl("/nonce").toString()),
            dpopManager = dpopManager
        )

        val claims = SignedJWT.parse(
            dpopManager.generateCredentialProof(
                credentialEndpoint = "https://issuer.example.com/credential",
                accessToken = "an-access-token"
            )
        ).jwtClaimsSet
        assertNull(claims.getStringClaim("nonce"))
    }

    @Test
    fun `extractNonceFromTokenResponse should return c nonce when present`() {
        val tokenResponse = TokenResponse(
            accessToken = "access-token",
            tokenType = "Bearer",
            cNonce = "nonce-123"
        )

        val nonce = NonceService.extractNonceFromTokenResponse(tokenResponse)

        assertEquals("nonce-123", nonce)
    }

    @Test
    fun `extractNonceFromTokenResponse should return null when c nonce is missing`() {
        val tokenResponse = TokenResponse(
            accessToken = "access-token",
            tokenType = "Bearer",
            cNonce = null
        )

        val nonce = NonceService.extractNonceFromTokenResponse(tokenResponse)

        assertNull(nonce)
    }

    private fun issuerMetadata(nonceEndpoint: String?) = IssuerMetadata(
        credentialIssuer = "https://issuer.example.com",
        credentialEndpoint = "https://issuer.example.com/credential",
        credentialFormat = CredentialFormat.LDP_VC,
        nonceEndpoint = nonceEndpoint
    )
}
