# AzureAuth <a href="https://github.com/Azure/AzureR"><img src="man/figures/logo.png" align="right" width=150 /></a>

[![CRAN](https://www.r-pkg.org/badges/version/AzureAuth)](https://cran.r-project.org/package=AzureAuth)
![Downloads](https://cranlogs.r-pkg.org/badges/AzureAuth)
[![Travis Build Status](https://travis-ci.org/Azure/AzureAuth.svg?branch=master)](https://travis-ci.org/Azure/AzureAuth)

AzureAuth provides [Azure Active Directory](https://docs.microsoft.com/azure/active-directory/develop/) (AAD) authentication functionality for R users of Microsoft's Azure cloud. Use this package to obtain OAuth 2.0 tokens for Azure services including Azure Resource Manager, Azure Storage and others. Both AAD v1.0 and v2.0 are supported.

The primary repo for this package is at https://github.com/Azure/AzureAuth; please submit issues and PRs there. It is also mirrored at the Cloudyr org at https://github.com/cloudyr/AzureAuth. You can install the development version of the package with `devtools::install_github("Azure/AzureAuth")`.

## Obtaining tokens

The main function in AzureAuth is `get_azure_token`, which obtains an OAuth token from AAD. The token is cached in a user-specific directory using the [rappdirs](https://github.com/r-lib/rappdirs) package, and future requests will use the cached token without needing you to reauthenticate.

```r
library(AzureAuth)

token <- get_azure_token(resource="myresource", tenant="mytenant", app="app_id", ...)
```

For reasons of CRAN policy, the first time AzureAuth is loaded, it will prompt you for permission to create this directory. Unless you have a specific reason otherwise, it's recommended that you allow the directory to be created. Note that most other cloud engineering tools save credentials in this way, including Docker, Kubernetes, and the Azure CLI itself. The prompt only appears in an interactive session; if AzureAuth is loaded in a batch script, the directory is not created if it doesn't already exist.

Other supplied functions include `list_azure_tokens`, `delete_azure_token` and `clean_token_directory`, to let you manage the token cache.

AzureAuth supports the following methods for authenticating with AAD: **authorization_code**, **device_code**, **client_credentials**, **resource_owner** and **on_behalf_of**.

1. Using the **authorization_code** method is a multi-step process. First, `get_azure_token` opens a login window in your browser, where you can enter your AAD credentials. In the background, it loads the [httpuv](https://github.com/rstudio/httpuv) package to listen on a local port. Once you have logged in, the AAD server redirects your browser to a local URL that contains an authorization code. `get_azure_token` retrieves this authorization code and sends it to the AAD access endpoint, which returns the OAuth token.

```r
# obtain a token using authorization_code
# no user credentials needed
get_azure_token("myresource", "mytenant", "app_id", auth_type="authorization_code")
```

2. The **device_code** method is similar in concept to authorization_code, but is meant for situations where you are unable to browse the Internet -- for example if you don't have a browser installed or your computer has input constraints. First, `get_azure_token` contacts the AAD devicecode endpoint, which responds with a login URL and an access code. You then visit the URL and enter the code, possibly using a different computer. Meanwhile, `get_azure_token` polls the AAD access endpoint for a token, which is provided once you have entered the code.

```r
# obtain a token using device_code
# no user credentials needed
get_azure_token("myresource", "mytenant", "app_id", auth_type="device_code")
```

3. The **client_credentials** method is much simpler than the above methods, requiring only one step. `get_azure_token` contacts the access endpoint, passing it the credentials. This can be either a client secret or a certificate, which you supply in the `password` or `certificate` argument respectively. Once the credentials are verified, the endpoint returns the token.

```r
# obtain a token using client_credentials
# supply credentials in password arg
get_azure_token("myresource", "mytenant", "app_id",
                password="client_secret", auth_type="client_credentials")

# can also supply a client certificate as a PEM/PFX file...
get_azure_token("myresource", "mytenant", "app_id",
                certificate="mycert.pem", auth_type="client_credentials")

# ... or as an object in Azure Key Vault
cert <- AzureKeyVault::key_vault("myvault")$certificates$get("mycert")
get_azure_token("myresource", "mytenant", "app_id",
                certificate=cert, auth_type="client_credentials")
```

4. The **resource_owner** method also requires only one step. In this method, `get_azure_token` passes your (personal) username and password to the AAD access endpoint, which validates your credentials and returns the token.

```r
# obtain a token using resource_owner
# supply credentials in username and password args
get_azure_token("myresource", "mytenant", "app_id",
                username="myusername", password="mypassword", auth_type="resource_owner")
```

5. The **on_behalf_of** method is used to authenticate with an Azure resource by passing a token obtained beforehand. It is mostly used by intermediate apps to authenticate for users. In particular, you can use this method to obtain tokens for multiple resources, while only requiring the user to authenticate once.

```r
# obtaining multiple tokens: authenticate (interactively) once...
tok0 <- get_azure_token("serviceapp_id", "mytenant", "clientapp_id", auth_type="authorization_code")
# ...then get tokens for each resource with on_behalf_of
tok1 <- get_azure_token("resource1", "mytenant," "serviceapp_id",
                        password="serviceapp_secret", auth_type="on_behalf_of", on_behalf_of=tok0)
tok2 <- get_azure_token("resource2", "mytenant," "serviceapp_id",
                        password="serviceapp_secret", auth_type="on_behalf_of", on_behalf_of=tok0)
```

If you don't specify the method, `get_azure_token` makes a best guess based on the presence or absence of the other authentication arguments, and whether httpuv is installed.

```r
# this will default to authorization_code if httpuv is installed, and device_code if not
get_azure_token("myresource", "mytenant", "app_id")

# this will use on_behalf_of method
get_azure_token("myresource", "mytenant", "app_id",
                password="client_secret", on_behalf_of=token)
```

### Managed identities

AzureAuth provides `get_managed_token` to obtain tokens from within a managed identity. This is a VM, service or container in Azure that can authenticate as itself, which removes the need to save secret passwords or certificates.

```r
# run this from within an Azure VM or container for which an identity has been setup
get_managed_token("myresource")
```

### Inside a web app

Using the interactive flows (authorization_code and device_code) from within a Shiny app requires separating the authorization (logging in to Azure) step from the token acquisition step. For this purpose, AzureAuth provides the `build_authorization_uri` and `get_device_creds` functions. You can use these from within your app to carry out the authorization, and then pass the resulting credentials to `get_azure_token` itself. See the "Authenticating from Shiny" vignette for an example app.

## Acknowledgements

The AzureAuth interface is based on the OAuth framework in the [httr](https://github.com/r-lib/httr) package, customised and streamlined for Azure. It is an independent implementation of OAuth, but benefited greatly from the work done by Hadley Wickham and the rest of the httr development team.

----
<a href="https://github.com/Azure/AzureR"><img src="https://github.com/Azure/AzureR/raw/master/images/logo2.png" width=800 /></a>

