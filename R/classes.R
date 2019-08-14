AzureTokenAuthCode <- R6::R6Class("AzureTokenAuthCode", inherit=AzureToken,

public=list(

    initialize=function(..., auth_code=NULL)
    {
        super$initialize(...)

        private$initfunc(auth_code)

        # v2.0 endpoint doesn't provide an expires_on field, set it here
        if(is.null(self$credentials$expires_on))
            self$credentials$expires_on <- as.character(decode_jwt(self$credentials$access_token)$payload$exp)

        # notify user if no refresh token
        if(is.null(self$credentials$refresh_token))
            private$norenew_alert()

        if(use_cache)
            self$cache()

        self
    }
),

private=list(

    initfunc=function(init_args)
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

        code <- init_args$auth_code
        if(is.null(code))
        {
            if(!requireNamespace("httpuv", quietly=TRUE))
                stop("httpuv package must be installed to use authorization_code method", call.=FALSE)

            code <- listen_for_authcode(auth_uri, redirect)
        }

        # contact token endpoint for token
        access_uri <- private$aad_uri("token")
        body <- c(self$client, code=code, redirect_uri=redirect, self$token_args)

        res <- httr::POST(access_uri, body=body, encode="form")
        self$credentials <- process_aad_response(res)
    }
))


AzureTokenDeviceCode <- R6::R6Class("AzureTokenDeviceCode", inherit=AzureToken,

private=list(

    initfunc=function(init_args)
    {
        creds <- init_args$device_creds
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

        res <- poll_for_token(access_uri, body, creds$interval, creds$expires_in)
        self$credentials <- process_aad_response(res)
    }
))


AzureTokenClientCreds <- R6::R6Class("AzureTokenClientCreds", inherit=AzureToken,

private=list(
    initfunc=function(init_args)
    {
        # contact token endpoint directly with client credentials
        uri <- private$aad_uri("token")
        body <- private$build_access_body()

        res <- httr::POST(uri, body=body, encode="form")
        self$credentials <- process_aad_response(res)
    }
))


AzureTokenResowner <- R6::R6Class("AzureTokenResowner", inherit=AzureToken,

private=list(
    initfunc=function(init_args)
    {
        # contact token endpoint directly with resource owner username/password
        uri <- private$aad_uri("token")
        body <- private$build_access_body()

        res <- httr::POST(uri, body=body, encode="form")
        self$credentials <- process_aad_response(res)
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

        res <- httr::GET(uri, headers, query=query)
        self$credentials <- process_aad_response(res)
    }
))
