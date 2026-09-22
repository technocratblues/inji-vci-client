package io.mosip.vciclient.exception

import okhttp3.Headers

private const val NETWORK_REQUEST_FAILED_CODE = "VCI-006"

class NetworkRequestFailedException : VCIClientException {

    var httpStatusCode: Int? = null
        private set
    var headers: Headers? = null
        private set

    constructor(message: String?) : super(
        code = NETWORK_REQUEST_FAILED_CODE,
        message = "Network request failed, details - $message"
    )

    constructor(
        message: String?,
        issuerErrorCode: String? = null,
        issuerErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(
        code = NETWORK_REQUEST_FAILED_CODE,
        message = "Network request failed, details - $message",
        issuerErrorCode = issuerErrorCode,
        issuerErrorDescription = issuerErrorDescription,
        cause = cause
    )

    constructor(
        message: String?,
        httpStatusCode: Int?,
        headers: Headers?,
        issuerErrorCode: String? = null,
        issuerErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(
        code = NETWORK_REQUEST_FAILED_CODE,
        message = "Network request failed, details - $message",
        issuerErrorCode = issuerErrorCode,
        issuerErrorDescription = issuerErrorDescription,
        cause = cause
    ) {
        this.httpStatusCode = httpStatusCode
        this.headers = headers
    }

    }