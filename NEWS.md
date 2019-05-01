# AzureAuth 1.0.2.9000

* Support providing a certificate via a PEM file, or an AzureKeyVault object.
* Support providing a path in the aad_host argument, for B2C logins.

# AzureAuth 1.0.2

* Corrections to vignette and readme.
* Make prompt to create caching directory more generic, since other AzureR packages will also use it.

# AzureAuth 1.0.1

* Export `decode_jwt`, a utility function to view the token data.
* Force tokens to be cached using version 2 of the RDS format. This is mostly to ensure backward compatibility if the default format used by `saveRDS` ever changes.

# AzureAuth 1.0.0

* Submitted to CRAN
