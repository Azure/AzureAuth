#' Azure OAuth authentication
#'
#' Azure OAuth 2.0 token classes, with an interface based on the [Token2.0 class][httr::Token2.0] in httr. Rather than calling the initialization methods directly, tokens should be created via [get_azure_token()].
#'
#' @docType class
#' @section Methods:
#' - `refresh`: Refreshes the token. For expired tokens without an associated refresh token, refreshing really means requesting a new token.
#' - `validate`: Checks if the token is still valid. If there is no associated refresh token, this just checks if the current time is less than the token's expiry time.
#' - `hash`: Computes an MD5 hash on the input fields of the object. Used internally for identification purposes when caching.
#' - `cache`: Stores the token on disk for use in future sessions.
#'
#' @seealso
#' [get_azure_token], [httr::Token]
#'
#' @format An R6 object representing an Azure Active Directory token and its associated credentials. The `AzureTokenV1` class is for AAD v1.0 tokens, and the `AzureTokenV2` class is for AAD v2.0 tokens. Objects of the AzureToken class should not be created directly.
#' @export
AzureToken <- R6::R6Class("AzureToken",

public=list(

    aad_host=NULL,
    tenant=NULL,
    auth_type=NULL,
    client=NULL,
    authorize_args=NULL,
    token_args=NULL,
    credentials=list(), # returned token details from host

    initialize=function(tenant, app, password=NULL, username=NULL, certificate=NULL, auth_type=NULL,
                        aad_host="https://login.microsoftonline.com/",
                        authorize_args=list(), token_args=list())
    {
        # fail if this constructor is called directly
        if(is.null(self$version))
            stop("Do not call this constructor directly; use get_azure_token() instead")

        self$aad_host <- aad_host
        self$tenant <- normalize_tenant(tenant)
        self$auth_type <- select_auth_type(password, username, certificate, auth_type)

        self$client <- aad_request_credentials(app, password, username, certificate, self$auth_type)

        self$authorize_args <- authorize_args
        self$token_args <- token_args

        # set the "real" init method based on auth type
        private$initfunc <- switch(self$auth_type,
            authorization_code=init_authcode,
            device_code=init_devcode,
            client_credentials=init_clientcred,
            resource_owner=init_resowner
        )
        environment(private$initfunc) <- parent.env(environment())

        tokenfile <- file.path(AzureR_dir(), self$hash())
        if(file.exists(tokenfile))
        {
            message("Loading cached token")
            private$load_from_cache(tokenfile)
            return(self$refresh())
        }

        # v2.0 endpoint doesn't provide an expires_on field, set it here
        self$credentials$expires_on <- as.character(floor(as.numeric(Sys.time())))

        res <- private$initfunc()
        creds <- process_aad_response(res)

        self$credentials <- utils::modifyList(self$credentials, creds)

        # notify user if interactive auth and no refresh token
        if(self$auth_type %in% c("authorization_code", "device_code") && is.null(self$credentials$refresh_token))
        {
            if(self$version == 1)
                message("Server did not provide a refresh token: please reauthenticate to refresh.")
            else message("Server did not provide a refresh token: you will have to reauthenticate to refresh.\n",
                         "Add the 'offline_access' scope to obtain a refresh token.")
        }

        self$cache()
        self
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
        now <- as.character(floor(as.numeric(Sys.time())))

        res <- if(!is.null(self$credentials$refresh_token))
        {
            body <- utils::modifyList(self$client,
                list(grant_type="refresh_token", refresh_token=self$credentials$refresh_token))
            body <- private$build_access_body(body)

            uri <- private$aad_endpoint("token")
            httr::POST(uri, body=body, encode="form")
        }
        else private$initfunc() # reauthenticate if no refresh token

        creds <- try(process_aad_response(res))
        if(inherits(creds, "try-error"))
        {
            delete_azure_token(hash=self$hash(), confirm=FALSE)
            stop("Unable to refresh token", call.=FALSE)
        }

        self$credentials <- utils::modifyList(list(expires_on=now), creds)

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

    load_from_cache=function(file)
    {
        token <- readRDS(file)
        if(!is_azure_token(token))
            stop("Invalid or corrupted cached token", call.=FALSE)
        self$credentials <- token$credentials
    },

    # member function to be filled in by initialize()
    initfunc=NULL
))


#' @rdname AzureToken
#' @export
AzureTokenV1 <- R6::R6Class("AzureTokenV1", inherit=AzureToken,

public=list(

    version=1, # for compatibility
    resource=NULL,

    initialize=function(resource, ...)
    {
        self$resource <- resource
        super$initialize(...)
    }
),

private=list(

    build_access_body=function(body=self$client)
    {
        stopifnot(is.list(self$token_args))

        # fill in cert assertion details
        body$client_assertion <- build_assertion(body$client_assertion,
            self$tenant, body$client_id, self$aad_host, self$version)

        c(body, self$authorize_args, resource=self$resource)
    },

    aad_endpoint=function(type)
    {
        uri <- httr::parse_url(self$aad_host)
        uri$path <- if(nchar(uri$path) == 0)
            file.path(self$tenant, "oauth2", type)
        else file.path(uri$path, type)
        httr::build_url(uri)
    }

))


#' @rdname AzureToken
#' @export
AzureTokenV2 <- R6::R6Class("AzureTokenV2", inherit=AzureToken,

public=list(

    version=2, # for compatibility
    scope=NULL,

    initialize=function(resource, ...)
    {
        self$scope <- sapply(resource, verify_v2_scope, USE.NAMES=FALSE)
        super$initialize(...)
    }
),

private=list(

    build_access_body=function(body=self$client)
    {
        stopifnot(is.list(self$token_args))

        # fill in cert assertion details
        body$client_assertion <- build_assertion(body$client_assertion,
            self$tenant, body$client_id, self$aad_host, self$version)

        c(body, self$authorize_args, scope=paste(self$scope, collapse=" "))
    },

    aad_endpoint=function(type)
    {
        uri <- httr::parse_url(self$aad_host)
        uri$path <- if(nchar(uri$path) == 0)
            file.path(self$tenant, "oauth2/v2.0", type)
        else file.path(uri$path, type)
        httr::build_url(uri)
    }
))

