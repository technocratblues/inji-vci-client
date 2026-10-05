package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.redirectToWeb

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mosip.vciclient.authorizationCodeFlow.implicitAuthorization.ImplicitAuthorizationRequestData
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.InteractionType
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request.AuthorizationRequestData
import io.mosip.vciclient.authorizationServer.AuthorizationUrlBuilder
import io.mosip.vciclient.authorizationServer.PushedAuthorizationRequestService
import io.mosip.vciclient.authorizationServer.PushedAuthorizationResponse
import io.mosip.vciclient.constants.OpenWebPageCallback
import io.mosip.vciclient.exception.InteractiveAuthorizationException
import io.mosip.vciclient.exception.PushedAuthorizationRequestException
import io.mosip.vciclient.pkce.PKCESessionManager
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertTrue

class RedirectToWebAuthorizationMethodServiceTest {

    private lateinit var openWebPage: OpenWebPageCallback

    @Before
    fun setup() {
        mockkObject(AuthorizationUrlBuilder)

        every {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrl(any())
        } returns "https://auth.example.com/authorize"

        openWebPage = mockk()
    }


    @Test
    fun `type should return redirect_to_web`() {
        val service = RedirectToWebAuthorizationMethodService(openWebPage)
        assertEquals(InteractionType.RedirectToWeb.value, service.type())
    }


    @Test
    fun `should throw if requestData is not ImplicitAuthorizationRequestData`() = runTest {
        val service = RedirectToWebAuthorizationMethodService(openWebPage)

        val ex = assertThrows<InteractiveAuthorizationException> {
            service.authorizeUser(mockk<AuthorizationRequestData>())
        }
        print(ex)
        assertTrue {
            ex.message.contains("RedirectToWebAuthorizationHandler expects ImplicitAuthorizationRequestData but received AuthorizationRequestData")
        }
    }


    @Test
    fun `should return success response when redirect returns authorization_code`() = runTest {
        coEvery {
            openWebPage.invoke(any())
        } returns mapOf(
            "code" to "auth-code-123",
            "auth_session" to "session-xyz"
        )

        val service = RedirectToWebAuthorizationMethodService(openWebPage)

        val request = standardRequest()

        val response = service.authorizeUser(request)

        assertEquals("success", response.status)
        assertEquals("auth-code-123", response.authorizationCode)
        assertEquals("session-xyz", response.authSession)
        assertNull(response.error)
        assertNull(response.errorDescription)
    }


    @Test
    fun `should return error response when redirect returns error`() = runTest {
        coEvery {
            openWebPage.invoke(any())
        } returns mapOf(
            "error" to "access_denied",
            "error_description" to "User denied consent"
        )

        val service = RedirectToWebAuthorizationMethodService(openWebPage)

        val response = service.authorizeUser(standardRequest())

        assertEquals("error", response.status)
        assertEquals("access_denied", response.error)
        assertEquals("User denied consent", response.errorDescription)
        assertNull(response.authorizationCode)
    }


    @Test
    fun `should throw if authorization_code is missing in successful response`() = runTest {
        coEvery {
            openWebPage.invoke(any())
        } returns mapOf(
            "auth_session" to "session-xyz"
        )

        val service = RedirectToWebAuthorizationMethodService(openWebPage)

        val ex = assertThrows<InteractiveAuthorizationException> {
            service.authorizeUser(standardRequest())
        }

        assertEquals(
            "Failed to authorize via interaction: Missing authorization_code in successful redirect response",
            ex.message
        )
    }


    @Test
    fun `should push authorization request and use short URL when PAR endpoint present`() = runTest {
        every {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrlWithRequestUri(any(), any(), any())
        } returns "https://auth.example.com/authorize?client_id=client-id&request_uri=urn:req:abc"

        val parService = mockk<PushedAuthorizationRequestService>()
        coEvery {
            parService.pushAuthorizationRequest(any())
        } returns PushedAuthorizationResponse("urn:req:abc", 90)

        coEvery { openWebPage.invoke(any()) } returns mapOf("code" to "auth-code-123")

        val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)
        val response = service.authorizeUser(parRequest())

        assertEquals("success", response.status)
        assertEquals("auth-code-123", response.authorizationCode)

        coVerify(exactly = 1) {
            parService.pushAuthorizationRequest(any())
        }
        io.mockk.verify(exactly = 1) {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrlWithRequestUri(
                "https://auth.example.com", "client-id", "urn:req:abc"
            )
        }
    }

    @Test
    fun `should throw and not open web page when PAR response has no request_uri`() =
        runTest {
            val parService = mockk<PushedAuthorizationRequestService>()
            coEvery {
                parService.pushAuthorizationRequest(any())
            } returns PushedAuthorizationResponse(null, 90)

            val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)

            val ex = assertThrows<PushedAuthorizationRequestException> {
                service.authorizeUser(parRequest(requirePushedAuthorizationRequests = true))
            }
            assertTrue {
                ex.message.contains("did not contain a request_uri")
            }

            coVerify(exactly = 0) { openWebPage.invoke(any()) }
        }

    @Test
    fun `should use long URL and not call PAR when PAR endpoint absent`() = runTest {
        val parService = mockk<PushedAuthorizationRequestService>()
        coEvery { openWebPage.invoke(any()) } returns mapOf("code" to "auth-code-123")

        val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)
        val response = service.authorizeUser(standardRequest())

        assertEquals("success", response.status)
        assertEquals("auth-code-123", response.authorizationCode)

        coVerify(exactly = 0) {
            parService.pushAuthorizationRequest(any())
        }
        io.mockk.verify(exactly = 1) {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrl(any())
        }
    }

    @Test
    fun `should push authorization request when PAR is mandatory`() = runTest {
        every {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrlWithRequestUri(any(), any(), any())
        } returns "https://auth.example.com/authorize?client_id=client-id&request_uri=urn:req:abc"

        val parService = mockk<PushedAuthorizationRequestService>()
        coEvery {
            parService.pushAuthorizationRequest(any())
        } returns PushedAuthorizationResponse("urn:req:abc", 90)

        coEvery { openWebPage.invoke(any()) } returns mapOf("code" to "auth-code-123")

        val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)
        val response = service.authorizeUser(parRequest(requirePushedAuthorizationRequests = true))

        assertEquals("success", response.status)
        io.mockk.verify(exactly = 0) {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrl(any())
        }
    }

    @Test
    fun `should use PAR when PAR is explicitly optional and PAR succeeds`() = runTest {
        every {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrlWithRequestUri(any(), any(), any())
        } returns "https://auth.example.com/authorize?client_id=client-id&request_uri=urn:req:abc"

        val parService = mockk<PushedAuthorizationRequestService>()
        coEvery {
            parService.pushAuthorizationRequest(any())
        } returns PushedAuthorizationResponse("urn:req:abc", 90)

        coEvery { openWebPage.invoke(any()) } returns mapOf("code" to "auth-code-123")

        val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)
        val response = service.authorizeUser(parRequest(requirePushedAuthorizationRequests = false))

        assertEquals("success", response.status)

        coVerify(exactly = 1) {
            parService.pushAuthorizationRequest(any())
        }
        io.mockk.verify(exactly = 1) {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrlWithRequestUri(
                "https://auth.example.com", "client-id", "urn:req:abc"
            )
        }
        io.mockk.verify(exactly = 0) {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrl(any())
        }
    }

    @Test
    fun `should throw and not fall back when PAR is mandatory and the PAR request fails`() =
        runTest {
            val parService = mockk<PushedAuthorizationRequestService>()
            coEvery {
                parService.pushAuthorizationRequest(any())
            } throws PushedAuthorizationRequestException("PAR request failed at endpoint: HTTP 400")

            val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)

            val ex = assertThrows<PushedAuthorizationRequestException> {
                service.authorizeUser(parRequest(requirePushedAuthorizationRequests = true))
            }
            assertTrue { ex.message.contains("PAR request failed") }

            coVerify(exactly = 0) { openWebPage.invoke(any()) }
            io.mockk.verify(exactly = 0) {
                AuthorizationUrlBuilder.buildAuthorizationRequestUrl(any())
            }
        }

    @Test
    fun `should throw when PAR is mandatory but no PAR endpoint is advertised`() = runTest {
        val parService = mockk<PushedAuthorizationRequestService>()
        val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)

        val ex = assertThrows<PushedAuthorizationRequestException> {
            service.authorizeUser(
                standardRequest(requirePushedAuthorizationRequests = true)
            )
        }
        assertTrue {
            ex.message.contains("did not advertise a pushed_authorization_request_endpoint")
        }

        coVerify(exactly = 0) { openWebPage.invoke(any()) }
        io.mockk.verify(exactly = 0) {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrl(any())
        }
    }

    @Test
    fun `should fall back to standard authorization request when optional PAR fails`() = runTest {
        val parService = mockk<PushedAuthorizationRequestService>()
        coEvery {
            parService.pushAuthorizationRequest(any())
        } throws PushedAuthorizationRequestException("PAR request failed at endpoint: HTTP 400")

        coEvery { openWebPage.invoke(any()) } returns mapOf("code" to "auth-code-123")

        val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)
        val response = service.authorizeUser(parRequest(requirePushedAuthorizationRequests = false))

        assertEquals("success", response.status)
        assertEquals("auth-code-123", response.authorizationCode)

        io.mockk.verify(exactly = 1) {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrl(any())
        }
    }

    @Test
    fun `should fall back to standard authorization request when PAR is omitted and PAR fails`() =
        runTest {
            val parService = mockk<PushedAuthorizationRequestService>()
            coEvery {
                parService.pushAuthorizationRequest(any())
            } throws PushedAuthorizationRequestException("PAR request failed at endpoint: timeout")

            coEvery { openWebPage.invoke(any()) } returns mapOf("code" to "auth-code-123")

            val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)
            val response = service.authorizeUser(parRequest())

            assertEquals("success", response.status)
            io.mockk.verify(exactly = 1) {
                AuthorizationUrlBuilder.buildAuthorizationRequestUrl(any())
            }
        }

    @Test
    fun `should fall back when optional PAR fails with a non PAR exception`() = runTest {
        val parService = mockk<PushedAuthorizationRequestService>()
        coEvery {
            parService.pushAuthorizationRequest(any())
        } throws IllegalStateException("unexpected failure")

        coEvery { openWebPage.invoke(any()) } returns mapOf("code" to "auth-code-123")

        val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)
        val response = service.authorizeUser(parRequest(requirePushedAuthorizationRequests = false))

        assertEquals("success", response.status)
        io.mockk.verify(exactly = 1) {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrl(any())
        }
    }

    @Test
    fun `should not fall back when mandatory PAR fails with a non PAR exception`() = runTest {
        val parService = mockk<PushedAuthorizationRequestService>()
        coEvery {
            parService.pushAuthorizationRequest(any())
        } throws IllegalStateException("unexpected failure")

        val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)

        assertThrows<IllegalStateException> {
            service.authorizeUser(parRequest(requirePushedAuthorizationRequests = true))
        }
        coVerify(exactly = 0) { openWebPage.invoke(any()) }
    }

    private fun parRequest(
        requirePushedAuthorizationRequests: Boolean? = null,
    ): ImplicitAuthorizationRequestData {
        return ImplicitAuthorizationRequestData(
            authorizeUrl = "https://auth.example.com",
            clientMetadata = ClientMetadata(
                clientId = "client-id",
                redirectUri = "app://callback"
            ),
            pkceSession = PKCESessionManager.PKCESession(
                codeVerifier = "verifier",
                codeChallenge = "challenge",
                state = "state",
                nonce = "nonce"
            ),
            scope = "openid",
            dpopJkt = "dpop",
            pushedAuthorizationRequestEndpoint = "https://as.example.com/as/par",
            requirePushedAuthorizationRequests = requirePushedAuthorizationRequests
        )
    }

    private fun standardRequest(
        requirePushedAuthorizationRequests: Boolean? = null,
    ): ImplicitAuthorizationRequestData {
        return ImplicitAuthorizationRequestData(
            authorizeUrl = "https://auth.example.com",
            clientMetadata = ClientMetadata(
                clientId = "client-id",
                redirectUri = "app://callback"
            ),
            pkceSession = PKCESessionManager.PKCESession(
                codeVerifier = "verifier",
                codeChallenge = "challenge",
                state = "state",
                nonce = "nonce"
            ),
            scope = "openid",
            dpopJkt = "dpop",
            requirePushedAuthorizationRequests = requirePushedAuthorizationRequests
        )
    }
}
