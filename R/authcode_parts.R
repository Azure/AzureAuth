#' Generate URI for the OAuth authorization code flow
#'
#' @param endpoint The base URL for the Azure Active Directory login endpoint, or an `aad_endpoint` object.
#' @param tenant Your tenant. This can be a name ("myaadtenant"), a fully qualified domain name ("myaadtenant.onmicrosoft.com" or "mycompanyname.com"), or a GUID.
#' @param app The client/app ID to use to authenticate with.
#' @param version The AAD version, either 1 or 2.
#' @param ... Named arguments that will be added to the authorization URI as query parameters.
#' @param .params Alternatively, a named list of query parameters. If supplied, this overrides arguments supplied in `...`.
#'
#' @return
#' An object of class `httr::url`, representing the _parsed_ authorization URI. You can call `httr::build_url` on this object to obtain the URI as a text string.
#' @export
aad_authorize_uri <- function(endpoint, ...)
{
    UseMethod("aad_authorize_uri")
}


#' @export
aad_authorize_uri.default <- function(endpoint="https://login.microsoftonline.com/", tenant=NULL, app=NULL, version=1,
                                      ..., .params=list(...))
{
    endpoint <- aad_endpoint(endpoint, normalize_tenant(tenant), normalize_aad_version(version), "authorize")
    aad_authorize_uri(endpoint, app, .params=.params)
}


#' @export
aad_authorize_uri.aad_endpoint <- function(endpoint, app=NULL, ..., .params=list(...))
{
    uri <- httr::parse_url(endpoint)

    if(!is_empty(.params) && (is.null(names(.params)) || any(names(.params) == "")))
        stop("All query parameters must be named", call.=FALSE)

    opts <- utils::modifyList(list(client_id=app), .params)

    uri$query <- opts
    uri
}

