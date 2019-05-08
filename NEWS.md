# AzureAuth 1.0.2.9000

* Much improved support for authenticating with a certificate. In the `certificate` argument, specify either the name of a PEM/PFX file, or an AzureKeyVault object representing a cert.
* Support providing a path in the `aad_host` argument, for Azure B2C logins. Note that B2C requires https redirect URIs, which are not currently supported by httpuv; rather than the authorization_code flow, use device_code or client_credentials.
* Fix bug that prevented `token_args` argument from being passed to the token endpoint.
* Add support for the `on_behalf_of` authorization flow.

# AzureAuth 1.0.2

* Corrections to vignette and readme.
* Make prompt to create caching directory more generic, since other AzureR packages will also use it.

# AzureAuth 1.0.1

* Export `decode_jwt`, a utility function to view the token data.
* Force tokens to be cached using version 2 of the RDS format. This is mostly to ensure backward compatibility if the default format used by `saveRDS` ever changes.

# AzureAuth 1.0.0

* Submitted to CRAN
