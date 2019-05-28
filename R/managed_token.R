get_managed_token <- function(resource)
{
    auth_type <- "managed"
    aad_host <- "http://169.254.169.254/metadata/identity/oauth2"
    AzureTokenV1$new(resource, tenant="common", app=NULL, auth_type=auth_type, aad_host=aad_host)
}
