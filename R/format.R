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

    if(is_azure_v1_token(token))
    {
        version <- "v1.0"
        res <- paste("resource", token$resource)
    }
    else
    {
        version <- "v2.0"
        res <- paste("scope", paste_v2_scopes(token$scope))
    }

    tenant <- token$tenant
    if(tenant == "common")
    {
        token_obj <- decode_jwt(token$credentials$access_token)
        tenant <- paste0(tenant, " / ", token_obj$payload$tid)
    }

    paste0("Azure Active Directory ", version, " token for ", res, "\n",
           "  Tenant: ", tenant, "\n",
           "  App ID: ", token$client$client_id, "\n",
           "  Authentication method: ", token$auth_type, "\n",
           "  Token valid from: ", format(obtained, usetz=TRUE), "  to: ", format(expiry, usetz=TRUE), "\n",
           "  MD5 hash of inputs: ", token$hash(), "\n")
}
