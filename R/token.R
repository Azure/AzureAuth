#' Manage Azure Active Directory OAuth 2.0 tokens
#'
#' Use these functions to authenticate with Azure Active Directory (AAD).
#'
#' @param resource For AAD v1.0, the URL of your resource host, or a GUID. For AAD v2.0, a character vector of scopes, each consisting of a URL or GUID along with a path designating the access scope. See 'Details' below.
#' @param tenant Your tenant. This can be a name ("myaadtenant"), a fully qualified domain name ("myaadtenant.onmicrosoft.com" or "mycompanyname.com"), or a GUID.
#' @param app The client/app ID to use to authenticate with.
#' @param password For most authentication flows, this is the password for the _app_ where needed, also known as the client secret. For the resource owner grant, this is your personal account password. See 'Details' below.
#' @param username Your AAD username, if using the resource owner grant. See 'Details' below.
#' @param certificate A file containing the certificate for authenticating with, an Azure Key Vault certificate object, or a call to the `cert_assertion` function to build a client assertion with a certificate. See 'Certificate authentication' below.
#' @param auth_type The authentication type. See 'Details' below.
#' @param aad_host URL for your AAD host. For the public Azure cloud, this is `https://login.microsoftonline.com/`. Change this if you are using a government or private cloud. Can also be a full URL, eg `https://mydomain.b2clogin.com/mydomain/other/path/names/oauth2` (this is relevant mainly for Azure B2C logins).
#' @param version The AAD version, either 1 or 2.
#' @param authorize_args An optional list of further parameters for the AAD authorization endpoint. These will be included in the request URI as query parameters. Only used if `auth_type="authorization_code"`.
#' @param token_args An optional list of further parameters for the token endpoint. These will be included in the body of the request for `get_azure_token`, or as URI query parameters for `get_managed_token`.
#' @param use_cache If TRUE and cached credentials exist, use them instead of obtaining a new token. Set this to FALSE to bypass the cache.
#' @param on_behalf_of For the on-behalf-of authentication type, a token. This should be either an AzureToken object, or a string containing the JWT-encoded token itself.
#' @param auth_code For the `authorization_code` flow, the code. Only used if `auth_type == "authorization_code"`.
#' @param device_creds For the `device_code` flow, the device credentials used to verify the session between the client and the server. Only used if `auth_type == "device_code"`.
#'
#' @details
#' `get_azure_token` does much the same thing as [httr::oauth2.0_token()], but customised for Azure. It obtains an OAuth token, first by checking if a cached value exists on disk, and if not, acquiring it from the AAD server. `delete_azure_token` deletes a cached token, and `list_azure_tokens` lists currently cached tokens.
#'
#' `get_managed_token` is a specialised function to acquire tokens for a _managed identity_. This is an Azure service, such as a VM or container, that has been assigned its own identity and can be granted access permissions like a regular user. The advantage of managed identities over the other authentication methods (see below) is that you don't have to store a secret password, which improves security. Note that `get_managed_token` can only be used from within the managed identity itself.
#'
#' The `resource` arg should be a single URL or GUID for AAD v1.0. For AAD v2.0, it should be a vector of _scopes_, where each scope consists of a URL or GUID along with a path that designates the type of access requested. If a v2.0 scope doesn't have a path, `get_azure_token` will append the `/.default` path with a warning. A special scope is `offline_access`, which requests a refresh token from AAD along with the access token: without this scope, you will have to reauthenticate if you want to refresh the token.
#'
#' The `auth_code` and `device_creds` arguments are intended for use in embedded scenarios, eg when AzureAuth is loaded from within a Shiny web app. They enable the flow authorization step to be separated from the token acquisition step, which is necessary within an app; you can generally ignore these arguments when using AzureAuth interactively or as part of an R script. See the help for [build_authorization_uri] for examples on their use.
#'
#' `token_hash` computes the MD5 hash of its arguments. This is used by AzureAuth to identify tokens for caching purposes. Note that tokens are only cached if you allowed AzureAuth to create a data directory at package startup.
#'
#' One particular use of the `authorize_args` argument is to specify a different redirect URI to the default; see the examples below.
#'
#' @section Authentication methods:
#' 1. Using the **authorization_code** method is a multi-step process. First, `get_azure_token` opens a login window in your browser, where you can enter your AAD credentials. In the background, it loads the [httpuv](https://github.com/rstudio/httpuv) package to listen on a local port. Once you have logged in, the AAD server redirects your browser to a local URL that contains an authorization code. `get_azure_token` retrieves this authorization code and sends it to the AAD access endpoint, which returns the OAuth token.
#'
#' 2. The **device_code** method is similar in concept to authorization_code, but is meant for situations where you are unable to browse the Internet -- for example if you don't have a browser installed or your computer has input constraints. First, `get_azure_token` contacts the AAD devicecode endpoint, which responds with a login URL and an access code. You then visit the URL and enter the code, possibly using a different computer. Meanwhile, `get_azure_token` polls the AAD access endpoint for a token, which is provided once you have entered the code.
#'
#' 3. The **client_credentials** method is much simpler than the above methods, requiring only one step. `get_azure_token` contacts the access endpoint, passing it either the app secret or the certificate assertion (which you supply in the `password` or `certificate` argument respectively). Once the credentials are verified, the endpoint returns the token. This is the method typically used by service accounts.
#'
#' 4. The **resource_owner** method also requires only one step. In this method, `get_azure_token` passes your (personal) username and password to the AAD access endpoint, which validates your credentials and returns the token.
#'
#' 5. The **on_behalf_of** method is used to authenticate with an Azure resource by passing a token obtained beforehand. It is mostly used by intermediate apps to authenticate for users. In particular, you can use this method to obtain tokens for multiple resources, while only requiring the user to authenticate once: see the examples below.
#'
#' If the authentication method is not specified, it is chosen based on the presence or absence of the other arguments, and whether httpuv is installed.
#'
#' The httpuv package must be installed to use the authorization_code method, as this requires a web server to listen on the (local) redirect URI. See [httr::oauth2.0_token] for more information; note that Azure does not support the `use_oob` feature of the httr OAuth 2.0 token class.
#'
#' Similarly, since the authorization_code method opens a browser to load the AAD authorization page, your machine must have an Internet browser installed that can be run from inside R. In particular, if you are using a Linux [Data Science Virtual Machine](https://azure.microsoft.com/en-us/services/virtual-machines/data-science-virtual-machines/) in Azure, you may run into difficulties; use one of the other methods instead.
#'
#' @section Certificate authentication:
#' OAuth tokens can be authenticated via an SSL/TLS certificate, which is considered more secure than a client secret. To do this, use the `certificate` argument, which can contain any of the following:
#' - The name of a PEM or PFX file, containing _both_ the private key and the public certificate.
#' - A certificate object from the AzureKeyVault package, representing a cert stored in the Key Vault service.
#' - A call to the `cert_assertion()` function to customise details of the requested token, eg the duration, expiry date, custom claims, etc. See the examples below.
#'
#' @section OpenID Connect:
#' `get_azure_token` can be used to obtain ID tokens along with regular OAuth access tokens, when using an interactive authentication flow (authorization_code or device_code). The behaviour depends on the AAD version:
#' - AAD v1.0 will return an ID token as well as the access token by default; you don't have to do anything extra. However, AAD v1.0 will not _refresh_ the ID token when it expires; you must reauthenticate to get a new one. To ensure you don't pull the cached version of the credentials, specify `use_cache=FALSE` in the calls to `get_azure_token`.
#' - Unlike AAD v1.0, AAD v2.0 does not return an ID token by default. To get a token, specify `openid` as a scope. On the other hand it _does_ refresh the ID token, so bypassing the cache is not needed.
#'
#' @section Caching:
#' AzureAuth differs from httr in its handling of token caching in a number of ways. First, caching is based on all the inputs to `get_azure_token` as listed above. Second, it defines its own directory for cached tokens, using the rappdirs package. On recent Windows versions, this will usually be in the location `C:\\Users\\(username)\\AppData\\Local\\AzureR`. On Linux, it will be in `~/.config/AzureR`, and on MacOS, it will be in `~/Library/Application Support/AzureR`. Note that a single directory is used for all tokens, and the working directory is not touched (which significantly lessens the risk of accidentally introducing cached tokens into source control).
#'
#' To list all cached tokens on disk, use `list_azure_tokens`. This returns a list of token objects, named according to their MD5 hashes.
#'
#' To delete a cached token, use `delete_azure_token`. This takes the same inputs as `get_azure_token`, or you can specify the MD5 hash directly in the `hash` argument.
#'
#' To delete _all_ cached tokens, use `clean_token_directory`.
#'
#' @section Value:
#' For `get_azure_token`, an object of class either `AzureTokenV1` or `AzureTokenV2` depending on whether the token is for AAD v1.0 or v2.0. For `list_azure_tokens`, a list of such objects retrieved from disk.
#'
#' @seealso
#' [AzureToken], [httr::oauth2.0_token], [httr::Token], [cert_assertion],
#' [build_authorization_uri], [get_device_creds]
#'
#' [Azure Active Directory for developers](https://docs.microsoft.com/en-us/azure/active-directory/develop/),
#' [Device code flow on OAuth.com](https://www.oauth.com/oauth2-servers/device-flow/token-request/),
#' [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749) for the gory details on how OAuth works
#'
#' @examples
#' \dontrun{
#'
#' # authenticate with Azure Resource Manager:
#' # no user credentials are supplied, so this will use the authorization_code
#' # method if httpuv is installed, and device_code if not
#' get_azure_token("https://management.azure.com/", tenant="mytenant", app="app_id")
#'
#' # you can force a specific authentication method with the auth_type argument
#' get_azure_token("https://management.azure.com/", tenant="mytenant", app="app_id",
#'     auth_type="device_code")
#'
#' # to default to the client_credentials method, supply the app secret as the password
#' get_azure_token("https://management.azure.com/", tenant="mytenant", app="app_id",
#'     password="app_secret")
#'
#' # authenticate to your resource with the resource_owner method: provide your username and password
#' get_azure_token("https://myresource/", tenant="mytenant", app="app_id",
#'     username="user", password="abcdefg")
#'
#' # obtaining multiple tokens: authenticate (interactively) once...
#' tok0 <- get_azure_token("serviceapp_id", tenant="mytenant", app="clientapp_id",
#'     auth_type="authorization_code")
#' # ...then get tokens for each resource (Resource Manager and MS Graph) with on_behalf_of
#' tok1 <- get_azure_token("https://management.azure.com/", tenant="mytenant", app="serviceapp_id",
#'     password="serviceapp_secret", on_behalf_of=tok0)
#' tok2 <- get_azure_token("https://graph.microsoft.com/", tenant="mytenant", app="serviceapp_id",
#'     password="serviceapp_secret", on_behalf_of=tok0)
#'
#'
#' # use a different redirect URI to the default localhost:1410
#' get_azure_token("https://management.azure.com/", tenant="mytenant", app="app_id",
#'     authorize_args=list(redirect_uri="http://localhost:8000"))
#'
#'
#' # request an AAD v1.0 token for Resource Manager (the default)
#' token1 <- get_azure_token("https://management.azure.com/", "mytenant", "app_id")
#'
#' # same request to AAD v2.0, along with a refresh token
#' token2 <- get_azure_token(c("https://management.azure.com/.default", "offline_access"),
#'     "mytenant", "app_id", version=2)
#'
#' # requesting multiple scopes (Microsoft Graph) with AAD 2.0
#' tok <- get_azure_token(c("https://graph.microsoft.com/User.Read.All",
#'                          "https://graph.microsoft.com/User.ReadWrite.All",
#'                          "https://graph.microsoft.com/Directory.ReadWrite.All",
#'                          "offline_access"),
#'     "mytenant", "app_id", version=2)
#'
#'
#' # list saved tokens
#' list_azure_tokens()
#'
#' # delete a saved token from disk
#' delete_azure_token(resource="https://myresource/", tenant="mytenant", app="app_id",
#'     username="user", password="abcdefg")
#'
#' # delete a saved token by specifying its MD5 hash
#' delete_azure_token(hash="7ea491716e5b10a77a673106f3f53bfd")
#'
#'
#' # authenticating for B2C logins (custom AAD host)
#' get_azure_token("https://mydomain.com", "mytenant", "app_id", "password",
#'     aad_host="https://mytenant.b2clogin.com/tfp/mytenant.onmicrosoft.com/custom/oauth2")
#'
#'
#' # authenticating with a certificate
#' get_azure_token("https://management.azure.com/", "mytenant", "app_id",
#'     certificate="mycert.pem")
#'
#' # authenticating with a certificate stored in Azure Key Vault
#' cert <- AzureKeyVault::key_vault("myvault")$certificates$get("mycert")
#' get_azure_token("https://management.azure.com/", "mytenant", "app_id",
#'     certificate=cert)
#'
#' # get a token valid for 2 hours (default is 1 hour)
#' get_azure_token("https://management.azure.com/", "mytenant", "app_id",
#'     certificate=cert_assertion("mycert.pem", duration=2*3600))
#'
#'
#' # ID token with AAD v1.0
#' # if you only want an ID token, set the resource to blank ("")
#' tok <- get_azure_token("", "mytenant", "app_id", use_cache=FALSE)
#' tok$credentials$id_token
#'
#' # ID token with AAD v2.0
#' tok2 <- get_azure_token(c("openid", "offline_access"), "mytenant", "app_id", version=2)
#' tok2$credentials$id_token
#'
#'
#' # get a token from within a managed identity (VM, container or service)
#' get_managed_token("https://management.azure.com/")
#'
#' }
#' @export
get_azure_token <- function(resource, tenant, app, password=NULL, username=NULL, certificate=NULL, auth_type=NULL,
                            aad_host="https://login.microsoftonline.com/", version=1,
                            authorize_args=list(), token_args=list(),
                            use_cache=TRUE, on_behalf_of=NULL, auth_code=NULL, device_creds=NULL)
{
    auth_type <- select_auth_type(password, username, certificate, auth_type, on_behalf_of)

    common_args <- list(
        resource=resource,
        tenant=tenant,
        app=app,
        password=password,
        username=username,
        certificate=certificate,
        aad_host=aad_host,
        version=version,
        token_args=token_args,
        use_cache=use_cache
    )

    switch(auth_type,
        authorization_code=
            AzureTokenAuthCode$new(common_args, authorize_args, auth_code),
        device_code=
            AzureTokenDeviceCode$new(common_args, device_creds),
        client_credentials=
            AzureTokenClientCreds$new(common_args),
        on_behalf_of=
            AzureTokenOnBehalfOf$new(common_args, on_behalf_of),
        resource_owner=
            AzureTokenResowner$new(common_args),
        stop("Unknown authentication method ", auth_type, call.=FALSE))
}


#' @param hash The MD5 hash of this token, computed from the above inputs. Used by `delete_azure_token` to identify a cached token to delete.
#' @param confirm For `delete_azure_token`, whether to prompt for confirmation before deleting a token.
#' @rdname get_azure_token
#' @export
delete_azure_token <- function(resource, tenant, app, password=NULL, username=NULL, certificate=NULL, auth_type=NULL,
                               aad_host="https://login.microsoftonline.com/", version=1,
                               authorize_args=list(), token_args=list(), on_behalf_of=NULL,
                               hash=NULL, confirm=TRUE)
{
    if(!dir.exists(AzureR_dir()))
        return(invisible(NULL))

    if(is.null(hash))
        hash <- token_hash(resource, tenant, app, password, username, certificate, auth_type, aad_host, version,
                           authorize_args, token_args, on_behalf_of)

    if(confirm && interactive())
    {
        yn <- readline(paste0("Do you really want to delete this Azure Active Directory token? (y/N) "))
        if(tolower(substr(yn, 1, 1)) != "y")
            return(invisible(NULL))
    }
    file.remove(file.path(AzureR_dir(), hash))
    invisible(NULL)
}


#' @rdname get_azure_token
#' @export
clean_token_directory <- function(confirm=TRUE)
{
    if(!dir.exists(AzureR_dir()))
        return(invisible(NULL))

    if(confirm && interactive())
    {
        yn <- readline(paste0("Do you really want to delete ALL saved Azure Active Directory tokens? (y/N) "))
        if(tolower(substr(yn, 1, 1)) != "y")
            return(invisible(NULL))
    }
    toks <- dir(AzureR_dir(), pattern="^[0-9a-f]{32}$", full.names=TRUE)
    file.remove(toks)
    invisible(NULL)
}


#' @rdname get_azure_token
#' @export
list_azure_tokens <- function()
{
    tokens <- dir(AzureR_dir(), pattern="[0-9a-f]{32}", full.names=TRUE)
    lst <- lapply(tokens, function(fname)
    {
        x <- try(readRDS(fname), silent=TRUE)
        if(is_azure_token(x))
            x
        else NULL
    })
    names(lst) <- basename(tokens)
    lst[!sapply(lst, is.null)]
}


#' @rdname get_azure_token
#' @export
token_hash <- function(resource, tenant, app, password=NULL, username=NULL, certificate=NULL, auth_type=NULL,
                       aad_host="https://login.microsoftonline.com/", version=1,
                       authorize_args=list(), token_args=list(), on_behalf_of=NULL)
{
    # reconstruct the hash for the token object from the inputs
    version <- normalize_aad_version(version)
    tenant <- normalize_tenant(tenant)
    auth_type <- select_auth_type(password, username, certificate, auth_type, on_behalf_of)
    client <- aad_request_credentials(app, password, username, certificate, auth_type, on_behalf_of)

    if(version == 1)
        scope <- NULL
    else
    {
        # ignore warnings about invalid scopes when computing hash
        scope <- suppressWarnings(sapply(resource, verify_v2_scope, USE.NAMES=FALSE))
        resource <- NULL
    }

    token_hash_internal(version, aad_host, tenant, auth_type, client, resource, scope,
                        authorize_args, token_args)
}


token_hash_internal <- function(...)
{
    msg <- serialize(list(...), NULL, version=2)
    paste(openssl::md5(msg[-(1:14)]), collapse="")
}


# handle different behaviour of file_path on Windows/Linux wrt trailing /
construct_path <- function(...)
{
    sub("/$", "", file.path(..., fsep="/"))
}


is_empty <- function(x)
{
    is.null(x) || length(x) == 0
}


#' @param object For `is_azure_token`, `is_azure_v1_token` and `is_azure_v2_token`, an R object.
#' @rdname get_azure_token
#' @export
is_azure_token <- function(object)
{
    R6::is.R6(object) && inherits(object, "AzureToken")
}


#' @rdname get_azure_token
#' @export
is_azure_v1_token <- function(object)
{
    is_azure_token(object) && inherits(object, "AzureTokenV1")
}


#' @rdname get_azure_token
#' @export
is_azure_v2_token <- function(object)
{
    is_azure_token(object) && inherits(object, "AzureTokenV2")
}
