#' Standalone OAuth authorization functions
#'
#' @param resource,tenant,app,aad_host,version See the corresponding arguments for [get_azure_token].
#' @param username For `build_authorization_uri`, an optional login hint to be sent to the authorization endpoint.
#' @param ... Named arguments that will be added to the authorization URI as query parameters.
#'
#' @details
#' These functions are mainly for use in embedded scenarios, such as within a Shiny web app. In this case, the interactive authentication flows (authorization code and device code) need to be split up so that the authorization step is handled separately from the token acquisition step. You should not need to use these functions inside a regular R session, or when executing an R batch script.
#'
#' @return
#' For `build_authorization_uri`, the authorization URI as a string. This can be set as a redirect from within a Shiny app's UI component.
#'
#' For `get_device_creds`, a list containing the following components:
#' - `user_code`: A short string to be shown to the user
#' - `device_code`: A long string to verify the session with the AAD server
#' - `verification_uri`: The URI the user should browse to in order to login
#' - `expires_in`: The duration in seconds for which the user and device codes are valid
#' - `interval`: The interval between polling requests to the AAD token endpoint
#' - `message`: A string with login instructions for the user
#'
#' @examples
#' build_authorization_uri("https://myresource", "mytenant", "app_id",
#'                         redirect_uri="http://localhost:8100")
#'
#' \dontrun{
#'
#' ## obtaining an authorization code separately to acquiring the token
#' # first, get the authorization URI
#' auth_uri <- build_authorization_uri("https://management.azure.com/", "mytenant", "app_id")
#' # browsing to the URI will log you in and redirect to another URI containing the auth code
#' browseURL(auth_uri)
#' # use the code to acquire the token
#' get_azure_token("https://management.azure.com/", "mytenant", "app_id",
#'     auth_code="code-from-redirect")
#'
#'
#' ## obtaining device credentials separately to acquiring the token
#' # first, contact the authorization endpoint to get the user and device codes
#' creds <- get_device_creds("https://management.azure.com/", "mytenant", "app_id")
#' # print the login instructions
#' creds$message
#' # use the creds to acquire the token
#' get_azure_token("https://management.azure.com/", "mytenant", "app_id",
#'     auth_type="device_code", device_creds=creds)
#'
#' }
#' @rdname authorization
#' @export
build_authorization_uri <- function(resource, tenant, app, username=NULL, ...,
                                    aad_host="https://login.microsoftonline.com/", version=1)
{
    version <- normalize_aad_version(version)
    default_opts <- list(
        client_id=app,
        response_type="code",
        redirect_uri="http://localhost:1410/",
        login_hint=username,
        state=paste0(sample(letters, 20, TRUE), collapse="") # random nonce
    )
    default_opts <- if(version == 1)
        c(default_opts, resource=resource)
    else c(default_opts, scope=paste_v2_scopes(resource))

    opts <- utils::modifyList(default_opts, list(...))

    aad_uri(aad_host, normalize_tenant(tenant), version, "authorize", opts)
}


#' @rdname authorization
#' @export
get_device_creds <- function(resource, tenant, app, aad_host="https://login.microsoftonline.com/", version=1)
{
    version <- normalize_aad_version(version)
    uri <- aad_uri(aad_host, normalize_tenant(tenant), version, "devicecode")
    body <- if(version == 1)
        list(resource=resource)
    else list(scope=paste_v2_scopes(resource))
    body <- c(body, client_id=app)

    res <- httr::POST(uri, body=body, encode="form")
    process_aad_response(res)
}
