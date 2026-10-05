package io.mosip.vciclient.authorizationServer

import org.junit.Assert.assertEquals
import org.junit.Test

class AuthorizationUrlBuilderTest {

    @Test
    fun `build should return exact expected URL using form-url-encoding`() {
        val actual = AuthorizationUrlBuilder.buildAuthorizationRequestUrl(
            AuthorizationRequest(
                baseUrl = "https://example.com/auth",
                client = AuthorizationClientDetails(
                    clientId = "myClientId",
                    redirectUri = "https://myapp.com/callback",
                    scope = "openid profile email"
                ),
                security = AuthorizationSecurityDetails(
                    state = "abc123",
                    codeChallenge = "xyzChallenge",
                    nonce = "randomNonce",
                    dpopJkt = "dpopJkt"
                )
            )
        )

        val expected = "https://example.com/auth" +
                "?client_id=myClientId" +
                "&redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback" +
                "&response_type=code" +
                "&scope=openid+profile+email" +
                "&state=abc123" +
                "&code_challenge=xyzChallenge" +
                "&code_challenge_method=S256" +
                "&nonce=randomNonce" +
                "&dpop_jkt=dpopJkt"

        assertEquals(expected, actual)
    }

    @Test
    fun `buildWithRequestUri should return short URL with client_id and request_uri`() {
        val actual = AuthorizationUrlBuilder.buildAuthorizationRequestUrlWithRequestUri(
            baseUrl = "https://example.com/auth",
            clientId = "myClientId",
            requestUri = "urn:ietf:params:oauth:request_uri:abc123"
        )

        val expected = "https://example.com/auth" +
                "?client_id=myClientId" +
                "&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc123"

        assertEquals(expected, actual)
    }

    @Test
    fun `build should append dpop_jkt when provided`() {
        val actual = AuthorizationUrlBuilder.buildAuthorizationRequestUrl(
            AuthorizationRequest(
                baseUrl = "https://example.com/auth",
                client = AuthorizationClientDetails(
                    clientId = "myClientId",
                    redirectUri = "https://myapp.com/callback",
                    scope = "openid"
                ),
                security = AuthorizationSecurityDetails(
                    state = "abc123",
                    codeChallenge = "xyzChallenge",
                    nonce = "randomNonce",
                    dpopJkt = "thumb-print-value"
                )
            )
        )

        assertEquals(true, actual.endsWith("&dpop_jkt=thumb-print-value"))
    }
}
