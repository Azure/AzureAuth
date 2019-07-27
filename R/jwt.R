#' Get raw access token (which is a JWT object)
#'
#' @param token A token object. This can be an object of class `AzureToken`, of class `httr::Token`, or a character string containing the encoded token.
#'
#' @details
#' An OAuth token is a _JSON Web Token_, which is a set of base64URL-encoded JSON objects containing the token credentials along with an optional (opaque) verification signature. `decode_jwt` decodes the credentials into an R object so they can be viewed. `extract_jwt` extracts the credentials from an R object of class `AzureToken` or `httr::Token`.
#'
#' Note that `decode_jwt` does not touch the token signature or attempt to verify the credentials. You should not rely on the decoded information without verifying it independently. Passing the token itself to Azure is safe, as Azure will carry out its own verification procedure.
#'
#' @return
#' For `extract_jwt`, the character string containing the encoded token, suitable for including in a HTTP query. For `decode_jwt`, a list containing up to 3 components: `header`, `payload` and `signature`.
#'
#' @seealso
#' [jwt.io](https://jwt.io), the main JWT informational site
#'
#' [jwt.ms](https://jwt.ms), Microsoft site to decode and explain JWTs
#'
#' [JWT Wikipedia entry](https://en.wikipedia.org/wiki/JSON_Web_Token)
#' @rdname jwt
#' @export
decode_jwt <- function(token)
{
    UseMethod("decode_jwt")
}


#' @rdname jwt
#' @export
decode_jwt.AzureToken <- function(token)
{
    decode_jwt(token$credentials$access_token)
}


#' @rdname jwt
#' @export
decode_jwt.Token <- function(token)
{
    decode_jwt(token$credentials$access_token)
}


#' @rdname jwt
#' @export
decode_jwt.character <- function(token)
{
    token <- as.list(strsplit(token, "\\.")[[1]])
    token[1:2] <- lapply(token[1:2], function(x)
        jsonlite::fromJSON(rawToChar(jose::base64url_decode(x))))

    names(token)[1:2] <- c("header", "payload")
    if(length(token) > 2)
        names(token)[3] <- "signature"

    token
}


#' @rdname jwt
#' @export
extract_jwt <- function(token)
{
    UseMethod("extract_jwt")
}


#' @rdname jwt
#' @export
extract_jwt.AzureToken <- function(token)
{
    token$credentials$access_token
}


#' @rdname jwt
#' @export
extract_jwt.Token <- function(token)
{
    token$credentials$access_token
}


#' @rdname jwt
#' @export
extract_jwt.character <- function(token)
{
    token
}

