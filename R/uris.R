#' Generate URI for the OAuth authorization code flow
#'
#' @param endpoint The base URL for the Azure Active Directory login endpoint, or an `aad_endpoint` object.
#' @param tenant,resource,app See the corresponding arguments for [get_azure_token].
#' @param password A client secret to be sent to the authorization endpoint, if the app requires it. Note that this is _not_ your personal account password.
#' @param username An optional login hint to be sent to the authorization endpoint.
#' @param version The AAD version, either 1 or 2.
#' @param ... Named arguments that will be added to the authorization URI as query parameters.
#'
#' @details
#' This function is mainly for use in embedded scenarios such as where AzureAuth is called from within a Shiny web app. In this case, the first stage of the authorization code flow (obtaining the code) must be handled separately from the second stage (using the code to obtain the token). The `authorization_uri` function returns the URI for obtaining the code, which can be set as a redirect from within a Shiny app's UI component.
#'
#' @return
#' An object of class `httr::url`, representing the _parsed_ authorization URI. You can call `httr::build_url` on this object to obtain the URI as a text string.
#' @export
authorization_uri <- function(endpoint, ...)
{
    UseMethod("authorization_uri")
}


#' @rdname authorization_uri
#' @export
authorization_uri.default <- function(endpoint="https://login.microsoftonline.com/", tenant, resource, app,
                                      password=NULL, username=NULL, ..., version=1)
{
    endpoint <- aad_endpoint(endpoint, normalize_tenant(tenant), normalize_aad_version(version), "authorize")
    authorization_uri(endpoint, resource, app, password, username, ...)
}


#' @rdname authorization_uri
#' @export
authorization_uri.aad_endpoint <- function(endpoint, resource, app, password=NULL, username=NULL, ...)
{
    if(!grepl("authorize/?$", endpoint))
        stop("Not an OAuth authorization endpoint", call.=FALSE)

    opts <- list(...)

    if(!is_empty(opts) && (is.null(names(opts)) || any(names(opts) == "")))
        stop("All query parameters must be named", call.=FALSE)

    default_opts <- list(
        client_id=app,
        response_type="code",
        redirect_uri="http://localhost:1410/",
        client_secret=password,
        login_hint=username,
        state=paste0(sample(letters, 20, TRUE), collapse="") # random nonce
    )

    default_opts <- if(inherits(endpoint, "aad_endpoint_v1"))
        c(default_opts, resource=resource)
    else c(default_opts, scope=paste(resource, collapse=" "))

    uri <- httr::parse_url(endpoint)
    uri$query <- utils::modifyList(default_opts, opts)
    uri
}


