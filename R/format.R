#' Format an AzureToken object
#'
#' @param token An Azure OAuth token.
#'
#' @rdname format
#' @export
format_auth_header <- function(token)
{
    stopifnot(is_azure_token(token))
    expiry <- as.POSIXct(as.numeric(token$credentials$expires_on), origin="1970-01-01")
    obtained <- expiry - as.numeric(token$credentials$expires_in)
    resource <- token$credentials$resource
    tenant <- sub("/.+$", "", httr::parse_url(token$endpoint$access)$path)
    app <- token$app$key

    auth_type <- if(token$params$client_credentials)
        "client_credentials"
    else if(token$params$use_device)
        "device_code"
    else if(!is.null(token$params$user_params$username))
        "resource_owner"
    else "authorization_code"

    hash <- token$hash()

    paste0("Azure Active Directory token for resource ", resource, "\n",
           "  Tenant: ", tenant, "\n",
           "  App ID: ", app, "\n",
           "  Authentication method: ", auth_type, "\n",
           "  Token valid from: ", format(obtained, usetz=TRUE), "  to: ", format(expiry, usetz=TRUE), "\n",
           "  MD5 hash of inputs: ", hash, "\n")
}
