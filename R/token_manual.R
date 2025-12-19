#' Manual Azure Token
#'
#' Create an Azure token object from a pre-existing access token string. This is useful
#' when you have obtained a token externally (e.g., via Azure CLI, Python, or another
#' authentication mechanism) and want to use it with the AzureR ecosystem.
#'
#' @docType class
#' @section Methods:
#' \itemize{
#'   \item \code{new(token, type, tenant, resource)}: Initialize a new manual token object.
#'   \item \code{refresh()}: Cannot refresh a manual token; issues a warning and returns self.
#'   \item \code{validate()}: Checks if the token has expired based on JWT claims.
#'   \item \code{can_refresh()}: Returns FALSE since manual tokens cannot be refreshed.
#'   \item \code{cache()}: No-op; manual tokens are not cached.
#' }
#'
#' @details
#' The \code{AzureManualToken} class provides a way to wrap an externally-obtained access
#' token string so it can be used with packages like \code{AzureGraph}, \code{AzureRMR},
#' and other AzureR family packages that expect an \code{AzureToken} object.
#'
#' If the token is a JWT (JSON Web Token), the class will attempt to parse it to extract
#' metadata such as the tenant ID, audience (resource), and expiration time. If parsing
#' fails (e.g., for opaque tokens), the class will still function but with limited metadata.
#'
#' Since manual tokens are managed externally, the \code{refresh()} method cannot obtain
#' a new token. When the token expires, you must create a new \code{AzureManualToken}
#' object with a fresh token string.
#'
#' @seealso
#' \code{\link{get_manual_token}}, \code{\link{AzureToken}}, \code{\link{decode_jwt}}
#'
#' @examples
#' \dontrun{
#' # Get a token externally (e.g., from Azure CLI)
#' # az account get-access-token --resource https://graph.microsoft.com
#' raw_token <- "eyJ0eXAiOiJKV1QiLC..."
#'
#' # Create a manual token object
#' token <- get_manual_token(raw_token)
#'
#' # Check if metadata was parsed
#' print(token$tenant)
#' print(token$resource)
#'
#' # Use with AzureGraph
#' library(AzureGraph)
#' gr <- ms_graph$new(token = token)
#' me <- gr$get_user("me")
#'
#' # Check token validity
#' token$validate()
#' }
#'
#' @format An R6 object of class \code{AzureManualToken}, inheriting from \code{AzureToken}.
#' @export
AzureManualToken <- R6::R6Class("AzureManualToken", inherit = AzureToken,

public = list(

    #' @description Initialize a manual token from a raw access token string.
    #' @param token A character string containing the access token.
    #' @param type The token type, usually "Bearer".
    #' @param tenant Optional tenant ID. If NULL, extracted from JWT claims.
    #' @param resource Optional resource/audience. If NULL, extracted from JWT claims.
    initialize = function(token, type = "Bearer", tenant = NULL, resource = NULL)
    {
        if(missing(token) || is.null(token) || !is.character(token) || nchar(token) == 0)
            stop("Must provide a non-empty token string", call. = FALSE)

        # Store the raw token
        private$raw_token <- token

        # Initialize credentials
        self$credentials <- list(
            access_token = token,
            token_type = type
        )

        # Set auth type
        self$auth_type <- "manual"

        # Default to v2.0 (modern tokens)
        self$version <- 2

        # Initialize client with placeholder (needed for format_auth_header)
        self$client <- list(client_id = "(external)")

        # Initialize other required fields
        self$aad_host <- "https://login.microsoftonline.com/"
        self$token_args <- list()
        self$authorize_args <- list()

        # Parse JWT claims (may fail for opaque tokens)
        claims <- try(decode_jwt(token)$payload, silent=TRUE)
        if(inherits(claims, "try-error"))
        {
            claims <- list()
            message("Note: Token could not be parsed as a JWT, metadata will be limited.")
        }

        # Extract tenant from tid claim
        if(!is.null(claims$tid))
            self$tenant <- claims$tid

        # Extract resource/audience from aud claim
        if(!is.null(claims$aud))
        {
            self$resource <- claims$aud
            # For v2.0 tokens, also set scope
            self$scope <- claims$aud
        }

        # Extract scopes if available (v2.0 tokens use scp claim)
        if(!is.null(claims$scp))
        {
            self$scope <- strsplit(claims$scp, " ")[[1]]
        }

        # Extract version from ver claim if available
        if(!is.null(claims$ver))
        {
            ver <- as.numeric(sub("^([0-9]+).*", "\\1", claims$ver))
            if(!is.na(ver) && ver %in% c(1, 2))
                self$version <- ver
        }

        # Set expiration time
        if(!is.null(claims$exp))
        {
            self$credentials$expires_on <- as.character(claims$exp)
        }

        # Calculate expires_in if we have both exp and iat
        if(!is.null(claims$exp) && !is.null(claims$iat))
        {
            self$credentials$expires_in <- as.character(claims$exp - claims$iat)
        }
        else if(!is.null(claims$exp))
        {
            # Estimate expires_in from current time
            self$credentials$expires_in <- as.character(claims$exp - as.numeric(Sys.time()))
        }

        # Override with user-provided values if specified
        if(!is.null(tenant))
            self$tenant <- tenant

        if(!is.null(resource))
        {
            self$resource <- resource
            self$scope <- resource
        }

        # Set defaults for any fields still NULL
        if(is.null(self$tenant))
            self$tenant <- "unknown"

        if(is.null(self$resource))
            self$resource <- "unknown"

        if(is.null(self$credentials$expires_on))
        {
            # Default to 1 hour from now if we couldn't parse expiration
            self$credentials$expires_on <- as.character(as.numeric(Sys.time()) + 3600)
            self$credentials$expires_in <- "3600"
            message("Note: Could not determine token expiration, assuming 1 hour validity.")
        }

        if(is.null(self$credentials$expires_in))
            self$credentials$expires_in <- "3600"

        invisible(self)
    },

    #' @description Refresh the token. Manual tokens cannot be refreshed.
    #' @return Returns self invisibly.
    refresh = function()
    {
        invisible(self)
    },

    #' @description Check if this token can be refreshed.
    #' @return Always returns FALSE for manual tokens.
    can_refresh = function()
    {
        FALSE
    },

    #' @description Cache the token. Manual tokens are not cached.
    #' @return Returns NULL invisibly.
    cache = function()
    {
        # Do not cache manual tokens - they are managed externally
        invisible(NULL)
    },

    #' @description Compute a hash for this token.
    #' @return An MD5 hash string based on the token content.
    hash = function()
    {
        # Hash based on the token string itself
        msg <- serialize(list(
            type = "manual",
            token = private$raw_token,
            tenant = self$tenant,
            resource = self$resource
        ), NULL, version = 2)
        paste(openssl::md5(msg[-(1:14)]), collapse = "")
    },

    #' @description Print the token object.
    print = function()
    {
        cat(format_auth_header(self))
        cat("
This is a manual token and cannot be refreshed.\n")
        invisible(self)
    }
),

private = list(
    raw_token = NULL,

    # Required by base class but not used for manual tokens
    initfunc = function(...) NULL
))


#' Get a manual Azure token
#'
#' Create an Azure token object from a pre-existing access token string. This is useful
#' when you have obtained a token externally (e.g., via Azure CLI, Python, or another
#' authentication mechanism) and want to use it with the AzureR ecosystem.
#'
#' @param token A character string containing the access token.
#' @param type The token type, usually "Bearer".
#' @param tenant Optional tenant ID. If NULL, will be extracted from JWT claims if possible.
#' @param resource Optional resource/audience URL or GUID. If NULL, will be extracted from
#'   JWT claims if possible.
#'
#' @details
#' This function creates an \code{\link{AzureManualToken}} object that wraps an externally-obtained

#' access token. The token object can then be used with packages like \code{AzureGraph},
#' \code{AzureRMR}, and other AzureR family packages.
#'
#' If the provided token is a JWT (JSON Web Token), the function will attempt to parse it
#' to extract metadata like tenant ID, resource, and expiration time. For opaque tokens
#' or tokens that cannot be parsed, you can provide the \code{tenant} and \code{resource}
#' parameters manually.
#'
#' @section Token sources:
#' Common ways to obtain tokens externally include:
#' \itemize{
#'   \item Azure CLI: \code{az account get-access-token --resource <resource>}
#'   \item Azure PowerShell: \code{Get-AzAccessToken -ResourceUrl <resource>}
#'   \item Python (azure-identity): \code{DefaultAzureCredential().get_token(<scope>)}
#'   \item MSAL libraries in various languages
#' }
#'
#' @section Limitations:
#' Manual tokens have the following limitations compared to tokens obtained via
#' \code{\link{get_azure_token}}:
#' \itemize{
#'   \item Cannot be automatically refreshed when they expire
#'   \item Are not cached to disk
#'   \item May have incomplete metadata if JWT parsing fails
#' }
#'
#' @return An object of class \code{AzureManualToken}, inheriting from \code{AzureToken}.
#'
#' @seealso
#' \code{\link{AzureManualToken}}, \code{\link{get_azure_token}}, \code{\link{decode_jwt}}
#'
#' @examples
#' \dontrun{
#' # Example: Use a token from Azure CLI
#' # First, get the token from command line:
#' # az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv
#'
#' raw_token <- "eyJ0eXAiOiJKV1QiLC..."
#' token <- get_manual_token(raw_token)
#'
#' # Check token properties
#' print(token)
#' token$validate()
#'
#' # Use with AzureGraph
#' library(AzureGraph)
#' gr <- ms_graph$new(token = token)
#'
#' # For opaque tokens, provide metadata explicitly
#' token2 <- get_manual_token(
#'     token = "opaque_token_string",
#'     tenant = "your-tenant-id",
#'     resource = "https://management.azure.com/"
#' )
#' }
#'
#' @export
get_manual_token <- function(token, type = "Bearer", tenant = NULL, resource = NULL)
{
    AzureManualToken$new(token = token, type = type, tenant = tenant, resource = resource)
}
