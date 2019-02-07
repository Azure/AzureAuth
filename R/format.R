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
    
    res <- if(token$version == 1)
        paste("resource", token$resource)
    else paste("scope", token$scope)

    version <- if(token$version == 1) "v1.0" else "v2.0"

    paste0("Azure Active Directory ", version, " token for ", res, "\n",
           "  Tenant: ", token$tenant, "\n",
           "  App ID: ", token$client$client_id, "\n",
           "  Authentication method: ", token$auth_type, "\n",
           "  Token valid from: ", format(obtained, usetz=TRUE), "  to: ", format(expiry, usetz=TRUE), "\n",
           "  MD5 hash of inputs: ", token$hash(), "\n")
}
