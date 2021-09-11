# AzureAuth 1.3.3

- Documentation update only:
  - Clarify that you can use `get_managed_token` to obtain tokens with a user-defined identity, not just a system identity.
  - Clarify the distinction between authentication and authorization in the `get_azure_token` help, and also in the Shiny vignette.
  - Add a webapp (Shiny) scenario to the "Common authentication scenarios" vignette.

# AzureAuth 1.3.2

- Change the default caching behaviour to disable the cache if running inside Shiny.
- Update Shiny vignette to clean up redirect page after authenticating (thanks to Tyler Littlefield).
- Revert the changed behaviour for caching directory creation in 1.3.1.
- Add a `create_AzureR_dir` function to create the caching directory manually. This can be useful not just for non-interactive sessions, but also Jupyter and R notebooks, which are not _technically_ interactive in the sense that they cannot read user input from a console prompt.

# AzureAuth 1.3.1

- Allow specifying the location of the token caching directory in the environment variable `R_AZURE_DATA_DIR`.
- Change `clean_token_directory` to actually clean the directory (delete all files). This is because the main non-token objects found here are AzureRMR and AzureGraph logins, which are orphaned once their backing tokens are deleted. Deleting them as well is less confusing, as a message will be displayed saying to create a new login.
- Always create the token caching directory, rather than asking first. This should result in consistent behaviour for both interactive and non-interactive sessions.
- Add a vignette outlining the app registration settings and `get_azure_token` arguments for some common authentication scenarios.

# AzureAuth 1.3.0

- Allow obtaining tokens for the `organizations` and `consumers` generic tenants, in addition to `common`.
- More robust handling of expiry time calculation for AAD v2.0 authentication.

# AzureAuth 1.2.5

- Change maintainer email address.

# AzureAuth 1.2.4

- Allow any scheme to be used in the URI for a token resource, not just HTTP\[S\].
- Documentation/vignette fixes.

# AzureAuth 1.2.3

* `is_guid`, `normalize_guid` and `normalize_tenant` now accept vector arguments. `normalize_guid` throws an error if any of its argument values is not a valid GUID.
* `get_azure_token` will now display the authentication method it chooses if the `auth_type` argument is not explicitly specified. To avoid surprises, it's still recommended that you specify `auth_type` when obtaining a token.
* New `load_azure_token` function to retrieve a token from the cache, given its hash value.
* Fixes to allow authenticating personal accounts without a tenant.

# AzureAuth 1.2.2

* Only call `utils::askYesNo` if R version is 3.5 or higher.

# AzureAuth 1.2.1

* Pass the resource and scope as explicit parameters to the AAD endpoint when refreshing a token. Among other things, this allows using a refresh token from one resource to obtain an access token for another resource.
* Use `utils::askYesNo` for prompts, eg when creating the AzureR caching directory and deleting tokens; this fixes a bug in reading the input. As a side-effect, Windows users who are using RGUI.exe will see a popup dialog box instead of a message in the terminal.

# AzureAuth 1.2.0

* Changes to token acquisition code to better integrate with Shiny. Use the `build_authorization_uri` and `get_device_creds` functions to initiate the authorization step from within a Shiny web app. `get_azure_token` has new `auth_code` and `device_creds` arguments for passing in authorization details obtained separately. See the "Authenticating from Shiny" vignette for a skeleton example app.
* Add `use_cache` argument to `get_azure_token` and `get_managed_token`, which controls whether to cache tokens. Set this to FALSE to skip reading cached credentials from disk, and to skip saving credentials to the cache.
* Make `decode_jwt` a generic, with methods for character strings, `AzureToken` objects and `httr::Token` objects.
* Add `extract_jwt` generic to get the actual token from within an R object, with methods for character strings, `AzureToken` objects and `httr::Token` objects.
* Fix bug in checking the expiry time for AAD v2.0 tokens.
* Extend `get_managed_token` to work from within Azure Functions.
* Refactor the underlying classes to represent authentication flows, which have a much greater impact on the program logic than AAD version. In place of `AzureTokenV1` and `AzureTokenV2` classes, there are now `AzureTokenAuthCode`, `AzureTokenDeviceCode`, `AzureTokenClientCreds`, `AzureTokenOnBehalfOf`, `AzureTokenResOwner`, and `AzureTokenManaged`. There should be no user-visible changes in behaviour arising from this.

# AzureAuth 1.1.1

* New `get_managed_token` function to obtain a token for a managed identity. Note this only works within a VM, service or container to which an identity has been assigned.

# AzureAuth 1.1.0

* Much improved support for authenticating with a certificate. In the `certificate` argument, specify either the name of a PEM/PFX file, or an AzureKeyVault object representing a cert.
* Support providing a path in the `aad_host` argument, for Azure B2C logins.
* Fix bug that prevented `token_args` argument from being passed to the token endpoint.
* If authentication fails using the `authorization_code` flow, print the AAD error message, if possible.
* Add support for the `on_behalf_of` authorization flow.

# AzureAuth 1.0.2

* Corrections to vignette and readme.
* Make prompt to create caching directory more generic, since other AzureR packages will also use it.

# AzureAuth 1.0.1

* Export `decode_jwt`, a utility function to view the token data.
* Force tokens to be cached using version 2 of the RDS format. This is mostly to ensure backward compatibility if the default format used by `saveRDS` ever changes.

# AzureAuth 1.0.0

* Submitted to CRAN
