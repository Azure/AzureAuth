#' Decode info in a token (which is a JWT object)
#'
#' @param token A string representing the encoded token.
#'
#' @details
#' An OAuth token is a _JSON Web Token_, which is a set of base64URL-encoded JSON objects containing the token credentials along with an optional (opaque) verification signature. `decode_jwt` decodes the credentials into an R object so they can be viewed.
#'
#' Note that `decode_jwt` does not touch the token signature or attempt to verify the credentials. You should not rely on the decoded information without verifying it independently. Passing the token itself to Azure is safe, as Azure will carry out its own verification procedure.
#'
#' @return
#' A list containing up to 3 components: `header`, `payload` and `signature`.
#'
#' @seealso
#' [jwt.io](https://jwt.io), the main JWT informational site
#'
#' [jwt.ms](https://jwt.ms), Microsoft site to decode and explain JWTs
#'
#' [JWT Wikipedia entry](https://en.wikipedia.org/wiki/JSON_Web_Token)
#' @export
decode_jwt <- function(token)
{
    token <- as.list(strsplit(token, "\\.")[[1]])
    token[1:2] <- lapply(token[1:2], function(x)
        jsonlite::fromJSON(rawToChar(jose::base64url_decode(x))))

    names(token)[1:2] <- c("header", "payload")
    if(length(token) > 2)
        names(token)[3] <- "signature"

    token
}


aad_request_credentials <- function(app, password, username, certificate, auth_type, on_behalf_of)
{
    object <- if(auth_type == "on_behalf_of")
        list(client_id=app, grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer")
    else list(client_id=app, grant_type=auth_type)

    if(auth_type == "resource_owner")
    {
        if(is.null(username) && is.null(password))
            stop("Must provide a username and password for resource_owner grant", call.=FALSE)
        object$grant_type <- "password"
        object$username <- username
        object$password <- password
    }
    else if(auth_type %in% c("client_credentials", "on_behalf_of"))
    {
        if(!is.null(password))
            object$client_secret <- password
        else if(!is.null(certificate))
        {
            object$client_assertion_type <- "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            object$client_assertion <- certificate  # not actual assertion: will be replaced later
        }
        else stop("Must provide either a client secret or certificate for client_credentials or on_behalf_of grant",
                  call.=FALSE)

        if(auth_type == "on_behalf_of")
        {
            if(is_empty(on_behalf_of))
                stop("Must provide an Azure token for on_behalf_of grant", call.=FALSE)

            object$requested_token_use <- "on_behalf_of"
            object$assertion <- if(is_azure_token(on_behalf_of))
                on_behalf_of$credentials$access_token
            else as.character(on_behalf_of)
        }
    }
    else if(auth_type == "authorization_code")
    {
        if(!is.null(password) && !is.null(username))
            stop("Cannot provide both a username and secret with authorization_code method", call.=FALSE)
        if(!is.null(username))
            object$login_hint <- username
        if(!is.null(password))
            object$client_secret <- password
    }

    object
}


normalize_aad_version <- function(v)
{
    if(v == "v1.0")
        v <- 1
    else if(v == "v2.0")
        v <- 2
    if(!(is.numeric(v) && v %in% c(1, 2)))
        stop("Invalid AAD version")
    v
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
    valid_uri <- grepl("^https?://", scope)
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


