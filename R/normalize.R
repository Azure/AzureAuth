#' Normalize GUID and tenant values
#'
#' These functions are used by `get_azure_token` to recognise and properly format tenant and app IDs.
#'
#' @param tenant For `normalize_tenant`, a string containing an Azure Active Directory tenant. This can be a name ("myaadtenant"), a fully qualified domain name ("myaadtenant.onmicrosoft.com" or "mycompanyname.com"), or a valid GUID.
#' @param x For `is_guid`, a character string; for `normalize_guid`, a string containing a _validly formatted_ GUID.
#'
#' @details
#' A tenant can be identified either by a GUID, or its name, or a fully-qualified domain name (FQDN). The rules for normalizing a tenant are:
#' 1. If `tenant` is recognised as a valid GUID, return its canonically formatted value
#' 2. Otherwise, if it is a FQDN, return it
#' 3. Otherwise, if it is not the string "common", append ".onmicrosoft.com" to it
#' 4. Otherwise, return the value of `tenant`
#'
#' See the link below for GUID formats recognised by these functions.
#'
#' @return
#' For `is_guid`, whether the argument is a validly formatted GUID.
#'
#' For `normalize_guid`, the GUID in canonical format. If the argument is not recognised as a GUID, it throws an error.
#'
#' For `normalize_tenant`, the normalized ID or name of the tenant.
#'
#' @seealso
#' [get_azure_token]
#'
#' [Parsing rules for GUIDs in .NET](https://docs.microsoft.com/en-us/dotnet/api/system.guid.parse]). `is_guid` and `normalize_guid` recognise the "N", "D", "B" and "P" formats.
#'
#' @examples
#'
#' is_guid("72f988bf-86f1-41af-91ab-2d7cd011db47")    # TRUE
#' is_guid("{72f988bf-86f1-41af-91ab-2d7cd011db47}")  # TRUE
#' is_guid("72f988bf-86f1-41af-91ab-2d7cd011db47}")   # FALSE (unmatched brace)
#' is_guid("microsoft")                               # FALSE
#'
#' # all of these return the same value
#' normalize_guid("72f988bf-86f1-41af-91ab-2d7cd011db47")
#' normalize_guid("{72f988bf-86f1-41af-91ab-2d7cd011db47}")
#' normalize_guid("(72f988bf-86f1-41af-91ab-2d7cd011db47)")
#' normalize_guid("72f988bf86f141af91ab2d7cd011db47")
#'
#' normalize_tenant("microsoft")     # returns 'microsoft.onmicrosoft.com'
#' normalize_tenant("microsoft.com") # returns 'microsoft.com'
#' normalize_tenant("72f988bf-86f1-41af-91ab-2d7cd011db47") # returns the GUID
#'
#' @export
#' @rdname guid
normalize_tenant <- function(tenant)
{
    # check if supplied a guid; if not, check if a fqdn;
    # if not, check if 'common'; if not, append '.onmicrosoft.com'
    if(is_guid(tenant))
        return(normalize_guid(tenant))

    if(!grepl("\\.", tenant) && tenant != "common")
        tenant <- paste(tenant, "onmicrosoft.com", sep=".")
    tenant
}


#' @export
#' @rdname guid
normalize_guid <- function(x)
{
    if(!is_guid(x))
        stop("Not a GUID", call.=FALSE)

    x <- sub("^[({]?([-0-9a-f]+)[})]$", "\\1", x)
    x <- gsub("-", "", x)
    return(paste(
        substr(x, 1, 8),
        substr(x, 9, 12),
        substr(x, 13, 16),
        substr(x, 17, 20),
        substr(x, 21, 32), sep="-"))
}


#' @export
#' @rdname guid
is_guid <- function(x)
{
    grepl("^[0-9a-f]{32}$", x) ||
    grepl("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", x) ||
    grepl("^\\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}}$", x) ||
    grepl("^\\([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\)$", x)
}
