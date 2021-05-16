select_auth_type <- function(password, username, certificate, auth_type, on_behalf_of)
{
    if(!is.null(auth_type))
    {
        if(!auth_type %in%
           c("authorization_code", "device_code", "client_credentials", "resource_owner", "on_behalf_of",
             "managed"))
            stop("Invalid authentication method")
        return(auth_type)
    }

    got_pwd <- !is.null(password)
    got_user <- !is.null(username)
    got_cert <- !is.null(certificate)
    got_httpuv <- system.file(package="httpuv") != ""

    auth_type <- if(got_pwd && got_user && !got_cert)
        "resource_owner"
    else if(!got_pwd && !got_user && !got_cert)
    {
        if(!got_httpuv)
        {
            message("httpuv not installed, defaulting to device code authentication")
            "device_code"
        }
        else "authorization_code"
    }
    else if(!got_pwd && !got_cert && got_user && got_httpuv)
        "authorization_code"
    else if((got_pwd && !got_user) || got_cert)
    {
        if(is_empty(on_behalf_of))
            "client_credentials"
        else "on_behalf_of"
    }
    else stop("Can't select authentication method", call.=FALSE)

    message("Using ", auth_type, " flow")
    auth_type
}


process_aad_response <- function(res)
{
    status <- httr::status_code(res)
    if(status >= 300)
    {
        cont <- httr::content(res)

        msg <- if(is.character(cont))
            cont
        else if(is.list(cont) && is.character(cont$error_description))
            cont$error_description
        else ""

        msg <- paste0("obtain Azure Active Directory token. Message:\n", sub("\\.$", "", msg))
        list(token=httr::stop_for_status(status, msg))
    }
    else httr::content(res)
}


# need to capture bad scopes before requesting auth code
# v2.0 endpoint will show error page rather than redirecting, causing get_azure_token to wait forever
verify_v2_scope <- function(scope)
{
    # some OpenID scopes get a pass
    openid_scopes <- c("openid", "email", "profile", "offline_access")
    if(scope %in% openid_scopes)
        return(scope)

    # but not all
    bad_scopes <- c("address", "phone")
    if(scope %in% bad_scopes)
        stop("Unsupported OpenID scope: ", scope, call.=FALSE)

    # is it a URI or GUID?
    valid_uri <- !is.null(httr::parse_url(scope)$scheme)
    valid_guid <- is_guid(sub("/.*$", "", scope))
    if(!valid_uri && !valid_guid)
        stop("Invalid scope (must be a URI or GUID): ", scope, call.=FALSE)

    # if a URI or GUID, check that there is a valid scope in the path
    if(valid_uri)
    {
        uri <- httr::parse_url(scope)
        if(uri$path == "")
        {
            warning("No path supplied for scope ", scope, "; setting to /.default", call.=FALSE)
            uri$path <- ".default"
            scope <- httr::build_url(uri)
        }
    }
    else
    {
        path <- sub("^[^/]+/?", "", scope)
        if(path == "")
        {
            warning("No path supplied for scope ", scope, "; setting to /.default", call.=FALSE)
            scope <- sub("//", "/", paste0(scope, "/.default"))
        }
    }
    scope
}


aad_uri <- function(aad_host, tenant, version, type, query=list())
{
    uri <- httr::parse_url(aad_host)
    uri$query <- query

    uri$path <- if(nchar(uri$path) == 0)
    {
        if(version == 1)
            file.path(tenant, "oauth2", type)
        else file.path(tenant, "oauth2/v2.0", type)
    }
    else file.path(uri$path, type)

    httr::build_url(uri)
}


paste_v2_scopes <- function(scope)
{
    paste(scope, collapse=" ")
}


# display confirmation prompt, return TRUE/FALSE (no NA)
get_confirmation <- function(msg, default=TRUE)
{
    ok <- if(getRversion() < numeric_version("3.5.0"))
    {
        msg <- paste(msg, if(default) "(Yes/no/cancel) " else "(yes/No/cancel) ")
        yn <- readline(msg)
        if(nchar(yn) == 0)
            default
        else tolower(substr(yn, 1, 1)) == "y"
    }
    else utils::askYesNo(msg, default)
    isTRUE(ok)
}


in_shiny <- function()
{
    ("shiny" %in% loadedNamespaces()) && shiny::isRunning()
}
