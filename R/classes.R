AzureTokenAuthCode <- R6::R6Class("AzureTokenAuthCode", inherit=AzureToken,

public=list(

    authorize_args=NULL,

    initialize=function(common_args, authorize_args, auth_code)
    {
        self$auth_type <- "authorization_code"
        self$authorize_args <- authorize_args
        do.call(super$initialize, c(common_args, auth_info=auth_code))

        # notify user if no refresh token
        if(is.null(self$credentials$refresh_token))
            norenew_alert(self$version)

        if(private$use_cache)
            self$cache()

        self
    }
),

private=list(

    initfunc=function(code=NULL)
    {
        stopifnot(is.list(self$token_args))
        stopifnot(is.list(self$authorize_args))

        opts <- utils::modifyList(list(
            resource=if(self$version == 1) self$resource else self$scope,
            tenant=self$tenant,
            app=self$client$client_id,
            username=self$client$login_hint,
            aad_host=self$aad_host,
            version=self$version
        ), self$authorize_args)

        auth_uri <- do.call(build_authorization_uri, opts)
        redirect <- httr::parse_url(auth_uri)$query$redirect_uri

        if(is.null(code))
        {
            if(!requireNamespace("httpuv", quietly=TRUE))
                stop("httpuv package must be installed to use authorization_code method", call.=FALSE)

            code <- listen_for_authcode(auth_uri, redirect)
        }

        # contact token endpoint for token
        access_uri <- private$aad_uri("token")
        body <- c(self$client, code=code, redirect_uri=redirect, self$token_args)

        httr::POST(access_uri, body=body, encode="form")
    },

    set_request_credentials=function(password, username, ...)
    {
        object <- list(client_id=app, grant_type=auth_type)

        if(!is.null(password) && !is.null(username))
            stop("Cannot provide both a username and secret with authorization_code method", call.=FALSE)
        if(!is.null(username))
            object$login_hint <- username
        if(!is.null(password))
            object$client_secret <- password

        self$client <- object
    }
))


AzureTokenDeviceCode <- R6::R6Class("AzureTokenDeviceCode", inherit=AzureToken,

public=list(

    initialize=function(common_args, device_creds)
    {
        self$auth_type <- "device_code"
        do.call(super$initialize, c(common_args, auth_info=device_creds))

        # notify user if no refresh token
        if(is.null(self$credentials$refresh_token))
            norenew_alert(self$version)

        if(private$use_cache)
            self$cache()

        self
    }
),

private=list(

    initfunc=function(creds=NULL)
    {
        if(is.null(creds))
        {
            creds <- get_device_creds(
                if(self$version == 1) self$resource else self$scope,
                tenant=self$tenant,
                app=self$client$client_id,
                aad_host=self$aad_host,
                version=self$version
            )
            cat(creds$message, "\n")
        }

        # poll token endpoint for token
        access_uri <- private$aad_uri("token")
        body <- c(self$client, code=creds$device_code)

        poll_for_token(access_uri, body, creds$interval, creds$expires_in)
    }
))


AzureTokenClientCreds <- R6::R6Class("AzureTokenClientCreds", inherit=AzureToken,

public=list(

    initialize=function(common_args, on_behalf_of=NULL)
    {
        self$auth_type <- if(is.null(on_behalf_of))
            "authorization_code"
        else "on_behalf_of"

        do.call(super$initialize, common_args)

        if(private$use_cache)
            self$cache()

        self
    }
),

private=list(
    initfunc=function(init_args)
    {
        # contact token endpoint directly with client credentials
        uri <- private$aad_uri("token")
        body <- private$build_access_body()

        httr::POST(uri, body=body, encode="form")
    }
))


AzureTokenResowner <- R6::R6Class("AzureTokenResowner", inherit=AzureToken,

private=list(
    initfunc=function(init_args)
    {
        # contact token endpoint directly with resource owner username/password
        uri <- private$aad_uri("token")
        body <- private$build_access_body()

        httr::POST(uri, body=body, encode="form")
    }
))


AzureTokenManaged <- R6::R6Class("AzureTokenManaged", inherit=AzureToken,

private=list(
    initfunc=function(init_args)
    {
        stopifnot(is.list(self$token_args))

        uri <- private$aad_uri("token")
        query <- utils::modifyList(self$token_args,
            list(`api-version`=getOption("azure_imds_version"), resource=self$resource))

        secret <- Sys.getenv("MSI_SECRET")
        headers <- if(secret != "")
            httr::add_headers(secret=secret)
        else httr::add_headers(metadata="true")

        httr::GET(uri, headers, query=query)
    }
))


norenew_alert <- function(version)
{
    if(version == 1)
        message("Server did not provide a refresh token: please reauthenticate to refresh.")
    else message("Server did not provide a refresh token: you will have to reauthenticate to refresh.\n",
                "Add the 'offline_access' scope to obtain a refresh token.")
}
