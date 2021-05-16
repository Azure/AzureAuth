#' @rdname get_azure_token
#' @export
get_managed_token <- function(resource, token_args=list(), use_cache=NULL)
{
    aad_host <- Sys.getenv("MSI_ENDPOINT", "http://169.254.169.254/metadata/identity/oauth2")
    AzureTokenManaged$new(resource, aad_host, token_args=token_args, use_cache=use_cache)
}
