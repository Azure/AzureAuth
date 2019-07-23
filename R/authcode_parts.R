aad_authorize_uri <- function(endpoint, ...)
{
    UseMethod("aad_authorize_uri")
}


aad_authorize_uri.default <- function(endpoint="https://login.microsoftonline.com/", tenant=NULL, app=NULL, version=1,
                                      ..., .params=list(...))
{
    endpoint <- aad_endpoint(endpoint, normalize_tenant(tenant), normalize_aad_version(version), "authorize")
    aad_authorize_uri(endpoint, app, .params=.params)
}


aad_authorize_uri.aad_endpoint <- function(endpoint, app=NULL, ..., .params=list(...))
{
    uri <- httr::parse_url(endpoint)

    if(!is_empty(.params) && (is.null(names(.params)) || any(names(.params) == "")))
        stop("All query parameters must be named", call.=FALSE)

    opts <- utils::modifyList(list(client_id=app), .params)

    uri$query <- opts
    uri
}

