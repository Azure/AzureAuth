#' @rdname get_azure_token
#' @export
get_managed_token <- function(resource, token_args=list(), use_cache=NULL)
{
    aad_host <- Sys.getenv("MSI_ENDPOINT", "http://169.254.169.254/metadata/identity/oauth2")

    # deal with situation where host url string already contains '/token'
    aad_host <- sub("/token$", "", aad_host)

    AzureTokenManaged$new(resource, aad_host, token_args=token_args, use_cache=use_cache)
}
