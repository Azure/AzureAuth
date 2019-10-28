#' Azure OAuth authentication
#'
#' Azure OAuth 2.0 token classes, with an interface based on the [Token2.0 class][httr::Token2.0] in httr. Rather than calling the initialization methods directly, tokens should be created via [get_azure_token()].
#'
#' @docType class
#' @section Methods:
#' - `refresh`: Refreshes the token. For expired tokens without an associated refresh token, refreshing really means requesting a new token.
#' - `validate`: Checks if the token has not yet expired. Note that a token may be invalid for reasons other than having expired, eg if it is revoked on the server.
#' - `hash`: Computes an MD5 hash on the input fields of the object. Used internally for identification purposes when caching.
#' - `cache`: Stores the token on disk for use in future sessions.
#'
#' @seealso
#' [get_azure_token], [httr::Token]
#'
#' @format An R6 object representing an Azure Active Directory token and its associated credentials. `AzureToken` is the base class, and the others inherit from it.
#' @export
AzureToken <- R6::R6Class("AzureToken",

public=list(

    version=NULL,
    resource=NULL,
    scope=NULL,
    aad_host=NULL,
    tenant=NULL,
    auth_type=NULL,
    client=NULL,
    token_args=list(),
    authorize_args=list(),
    credentials=NULL, # returned token details from host

    initialize=function(resource, tenant, app, password=NULL, username=NULL, certificate=NULL,
                        aad_host="https://login.microsoftonline.com/", version=1,
                        authorize_args=list(), token_args=list(),
                        use_cache=TRUE, auth_info=NULL)
    {
        if(is.null(private$initfunc))
            stop("Do not call this constructor directly; use get_azure_token() instead")

        self$version <- normalize_aad_version(version)
        if(self$version == 1)
        {
            if(length(resource) != 1)
                stop("Resource for Azure Active Directory v1.0 token must be a single string", call.=FALSE)
            self$resource <- resource
        }
        else self$scope <- sapply(resource, verify_v2_scope, USE.NAMES=FALSE)

        self$aad_host <- aad_host
        self$tenant <- normalize_tenant(tenant)
        self$token_args <- token_args
        private$use_cache <- use_cache

        # use_cache = NA means return dummy object: initialize fields, but don't contact AAD
        if(is.na(use_cache))
            return()

        if(use_cache)
            private$load_cached_credentials()

        if(is.null(self$credentials))
        {
            res <- private$initfunc(auth_info)
            self$credentials <- process_aad_response(res)
        }
        private$set_expiry_time()

        if(private$use_cache)
            self$cache()
    },

    cache=function()
    {
        if(dir.exists(AzureR_dir()))
        {
            filename <- file.path(AzureR_dir(), self$hash())
            saveRDS(self, filename, version=2)
        }
        invisible(NULL)
    },

    hash=function()
    {
        token_hash_internal(self$version, self$aad_host, self$tenant, self$auth_type, self$client,
                            self$resource, self$scope, self$authorize_args, self$token_args)
    },

    validate=function()
    {
        expdate <- as.POSIXct(as.numeric(self$credentials$expires_on), origin="1970-01-01")
        curdate <- Sys.time()
        curdate < expdate
    },

    can_refresh=function()
    {
        TRUE
    },

    refresh=function()
    {
        res <- if(!is.null(self$credentials$refresh_token))
        {
            body <- list(grant_type="refresh_token",
                client_id=self$client$client_id,
                client_secret=self$client$client_secret,
                resource=self$resource,
                scope=paste_v2_scopes(self$scope),
                client_assertion=self$client$client_assertion,
                client_assertion_type=self$client$client_assertion_type,
                refresh_token=self$credentials$refresh_token
            )

            uri <- private$aad_uri("token")
            httr::POST(uri, body=body, encode="form")
        }
        else private$initfunc() # reauthenticate if no refresh token (cannot reuse any supplied creds)

        creds <- try(process_aad_response(res))
        if(inherits(creds, "try-error"))
        {
            delete_azure_token(hash=self$hash(), confirm=FALSE)
            stop("Unable to refresh token", call.=FALSE)
        }

        self$credentials <- creds
        private$set_expiry_time()

        if(private$use_cache)
            self$cache()
        invisible(self)
    },

    print=function()
    {
        cat(format_auth_header(self))
        invisible(self)
    }
),

private=list(

    use_cache=NULL,

    load_cached_credentials=function()
    {
        tokenfile <- file.path(AzureR_dir(), self$hash())
        if(!file.exists(tokenfile))
            return(NULL)

        message("Loading cached token")
        token <- readRDS(tokenfile)
        if(!is_azure_token(token))
        {
            file.remove(tokenfile)
            stop("Invalid or corrupted cached token", call.=FALSE)
        }

        self$credentials <- token$credentials
        if(!self$validate())
            self$refresh()
    },

    set_expiry_time=function()
    {
        # v2.0 endpoint doesn't provide an expires_on field, set it here
        if(is.null(self$credentials$expires_on))
        {
            expiry <- try(as.character(decode_jwt(self$credentials$access_token)$payload$exp), silent=TRUE)
            if(inherits(expiry, "try-error"))
            {
                expiry <- try(as.character(decode_jwt(self$credentials$id_token)$payload$exp), silent=TRUE)
                if(inherits(expiry, "try-error"))
                    stop("Bad access token, expiry date not found", call.=FALSE)
            }
            self$credentials$expires_on <- expiry
        }
    },

    aad_uri=function(type, ...)
    {
        aad_uri(self$aad_host, self$tenant, self$version, type, list(...))
    },

    build_access_body=function(body=self$client)
    {
        stopifnot(is.list(self$token_args))

        # fill in cert assertion details
        body$client_assertion <- build_assertion(body$client_assertion,
            self$tenant, body$client_id, self$aad_host, self$version)

        c(body, self$token_args,
            if(self$version == 1)
                list(resource=self$resource)
            else list(scope=paste_v2_scopes(self$scope))
        )
    }
))

