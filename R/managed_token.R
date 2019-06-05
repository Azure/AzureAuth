#' @rdname get_azure_token
#' @export
get_managed_token <- function(resource, token_args=list())
{
    auth_type <- "managed"
    aad_host <- "http://169.254.169.254/metadata/identity/oauth2"
    AzureTokenV1$new(resource, tenant="common", app=NULL, auth_type=auth_type, aad_host=aad_host, token_args=token_args)
}
