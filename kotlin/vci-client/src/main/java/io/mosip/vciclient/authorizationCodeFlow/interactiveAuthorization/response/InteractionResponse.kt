package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.response

abstract class InteractionResponse(
    @Transient
    open val status: String?,
    @Transient
    open val type: String?,
    @Transient
    open val authSession: String?,
) {

    init {
        validateCommonFields()
    }

    private fun validateCommonFields() {
        require (!status.isNullOrBlank()) {
            "Missing or empty 'status' field"
        }

        if (status == "require_interaction") {
            require (!type.isNullOrBlank()) {
                "'type' is required when status is 'require_interaction'"
            }
            require(!authSession.isNullOrBlank()) {
                "'authSession' is required when status is 'require_interaction'"
            }
        }
    }

    abstract fun validate()
}