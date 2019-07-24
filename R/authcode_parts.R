#' Generate URI for the OAuth authorization code flow
#'
#' @param endpoint The base URL for the Azure Active Directory login endpoint, or an `aad_endpoint` object.
#' @param tenant Your tenant. This can be a name ("myaadtenant"), a fully qualified domain name ("myaadtenant.onmicrosoft.com" or "mycompanyname.com"), or a GUID.
#' @param app The client/app ID to use to authenticate with.
#' @param version The AAD version, either 1 or 2.
#' @param ... Named arguments that will be added to the authorization URI as query parameters.
#'
#' @return
#' An object of class `httr::url`, representing the _parsed_ authorization URI. You can call `httr::build_url` on this object to obtain the URI as a text string.
#' @export
aad_authorize_uri <- function(endpoint, ...)
{
    UseMethod("aad_authorize_uri")
}


#' @export
aad_authorize_uri.default <- function(endpoint="https://login.microsoftonline.com/", tenant, resource, app,
                                      password=NULL, username=NULL, ..., version=1)
{
    endpoint <- aad_endpoint(endpoint, normalize_tenant(tenant), normalize_aad_version(version), "authorize")
    aad_authorize_uri(endpoint, resource, app, password, username, ...)
}


#' @export
aad_authorize_uri.aad_endpoint <- function(endpoint, resource, app, password=NULL, username=NULL, ...)
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

