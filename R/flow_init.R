#' Generate URI for the OAuth authorization code flow
#'
#' @param resource,tenant,app See the corresponding arguments for [get_azure_token].
#' @param password A client secret to be sent to the authorization endpoint, if the app requires it. Note that this is _not_ your personal account password.
#' @param username An optional login hint to be sent to the authorization endpoint.
#' @param aad_host The base URL for the Azure Active Directory login endpoint.
#' @param version The AAD version, either 1 or 2.
#' @param ... Named arguments that will be added to the authorization URI as query parameters.
#'
#' @details
#' This function is mainly for use in embedded scenarios, such as within a Shiny web app. In this case, the first stage of the authorization code flow (obtaining the code) must be handled separately from the second stage (using the code to obtain the token). The `get_authorization_uri` function returns the URI for obtaining the code, which can be set as a redirect from within a Shiny app's UI component.
#'
#' @return
#' The authorization URI as a string.
#' @export
build_authorization_uri <- function(resource, tenant, app, password=NULL, username=NULL, ...,
                                    aad_host="https://login.microsoftonline.com/", version=1)
{
    version <- normalize_aad_version(version)
    default_opts <- list(
        client_id=app,
        response_type="code",
        redirect_uri="http://localhost:1410/",
        client_secret=password,
        login_hint=username,
        state=paste0(sample(letters, 20, TRUE), collapse="") # random nonce
    )
    default_opts <- if(version == 1)
        c(default_opts, resource=resource)
    else c(default_opts, scope=paste(resource, collapse=" "))

    opts <- utils::modifyList(default_opts, list(...))

    aad_uri(aad_host, normalize_tenant(tenant), version, "authorize", opts)
}


#' Initialize the OAuth device code flow
#'
#' @param resource,tenant,app,aad_host,version See the corresponding arguments for [get_azure_token].
#'
#' @details
#' This function is mainly for use in embedded scenarios, such as within a Shiny web app. In this case, the first stage of the device code flow (obtaining the code and displaying it to the user) must be handled separately from the second stage (polling the endpoint for the token). The `request_device_code` function returns a list containing the user and authorization codes, plus a message to be displayed to the user.
#'
#' @return
#' A list, containing the following components:
#' - `user_code`: A short string to be shown to the user
#' - `device_code`: A long string to verify the session with the AAD server
#' - `verification_uri`: The URI the user should browse to in order to login
#' - `expires_in`: The duration in seconds for which the user and device codes are valid
#' - `interval`: The interval between polling requests to the AAD token endpoint
#' - `message`: A string with login instructions for the user
#' @export
request_device_code <- function(resource, tenant, app, aad_host="https://login.microsoftonline.com/", version=1)
{
    version <- normalize_aad_version(version)
    uri <- aad_uri(aad_host, normalize_tenant(tenant), version, "devicecode")
    body <- if(version == 1)
        list(resource=resource)
    else list(scope=paste(resource, collapse=" "))
    body <- c(body, client_id=app)

    res <- httr::POST(uri, body=body, encode="form")
    process_aad_response(res)
}
