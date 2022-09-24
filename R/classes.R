#' @rdname AzureToken
#' @export
AzureTokenAuthCode <- R6::R6Class("AzureTokenAuthCode", inherit=AzureToken,

public=list(

    initialize=function(common_args, authorize_args, auth_code)
    {
        self$auth_type <- "authorization_code"
        self$authorize_args <- authorize_args
        with(common_args,
            private$set_request_credentials(app, password, username))
        do.call(super$initialize, c(common_args, list(auth_info=auth_code)))

        # notify user if no refresh token
        if(!is.null(self$credentials) && is.null(self$credentials$refresh_token))
            norenew_alert(self$version)
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

    set_request_credentials=function(app, password, username)
    {
        object <- list(client_id=app, grant_type="authorization_code")

        if(!is.null(username))
            object$login_hint <- username
        if(!is.null(password))
            object$client_secret <- password

        self$client <- object
    }
))


#' @rdname AzureToken
#' @export
AzureTokenDeviceCode <- R6::R6Class("AzureTokenDeviceCode", inherit=AzureToken,

public=list(

    initialize=function(common_args, device_creds)
    {
        self$auth_type <- "device_code"
        with(common_args,
            private$set_request_credentials(app))
        do.call(super$initialize, c(common_args, list(auth_info=device_creds)))

        # notify user if no refresh token
        if(!is.null(self$credentials) && is.null(self$credentials$refresh_token))
            norenew_alert(self$version)
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
    },

    set_request_credentials=function(app)
    {
        self$client <- list(client_id=app, grant_type="device_code")
    }
))


#' @rdname AzureToken
#' @export
AzureTokenClientCreds <- R6::R6Class("AzureTokenClientCreds", inherit=AzureToken,

public=list(

    initialize=function(common_args)
    {
        self$auth_type <- "client_credentials"
        with(common_args,
            private$set_request_credentials(app, password, certificate))
        do.call(super$initialize, common_args)
    }
),

private=list(

    initfunc=function(init_args)
    {
        # contact token endpoint directly with client credentials
        uri <- private$aad_uri("token")
        body <- private$build_access_body()

        httr::POST(uri, body=body, encode="form")
    },

    set_request_credentials=function(app, password, certificate)
    {
        object <- list(client_id=app, grant_type="client_credentials")

        if(!is.null(password))
            object$client_secret <- password
        else if(!is.null(certificate))
        {
            object$client_assertion_type <- "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            object$client_assertion <- certificate  # not actual assertion: will be replaced later
        }
        else stop("Must provide either a client secret or certificate for client_credentials grant",
                  call.=FALSE)

        self$client <- object
    }
))


#' @rdname AzureToken
#' @export
AzureTokenOnBehalfOf <- R6::R6Class("AzureTokenOnBehalfOf", inherit=AzureToken,

public=list(

    initialize=function(common_args, on_behalf_of)
    {
        self$auth_type <- "on_behalf_of"
        with(common_args,
            private$set_request_credentials(app, password, certificate, on_behalf_of))
        do.call(super$initialize, common_args)
    }
),

private=list(

    initfunc=function(init_args)
    {
        # contact token endpoint directly with client credentials
        uri <- private$aad_uri("token")
        body <- private$build_access_body()

        httr::POST(uri, body=body, encode="form")
    },

    set_request_credentials=function(app, password, certificate, on_behalf_of)
    {
        if(is_empty(on_behalf_of))
            stop("Must provide an Azure token for on_behalf_of grant", call.=FALSE)

        object <- list(client_id=app, grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer")

        if(!is.null(password))
            object$client_secret <- password
        else if(!is.null(certificate))
        {
            object$client_assertion_type <- "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            object$client_assertion <- certificate  # not actual assertion: will be replaced later
        }
        else stop("Must provide either a client secret or certificate for on_behalf_of grant",
                  call.=FALSE)

        object$requested_token_use <- "on_behalf_of"
        object$assertion <- extract_jwt(on_behalf_of)

        self$client <- object
    }
))


#' @rdname AzureToken
#' @export
AzureTokenResOwner <- R6::R6Class("AzureTokenResOwner", inherit=AzureToken,

public=list(

    initialize=function(common_args)
    {
        self$auth_type <- "resource_owner"
        with(common_args,
            private$set_request_credentials(app, password, username))
        do.call(super$initialize, common_args)
    }
),

private=list(

    initfunc=function(init_args)
    {
        # contact token endpoint directly with resource owner username/password
        uri <- private$aad_uri("token")
        body <- private$build_access_body()

        httr::POST(uri, body=body, encode="form")
    },

    set_request_credentials=function(app, password, username)
    {
        object <- list(client_id=app, grant_type="password")

        if(is.null(username) && is.null(password))
            stop("Must provide a username and password for resource_owner grant", call.=FALSE)

        object$username <- username
        object$password <- password

        self$client <- object
    }
))


#' @rdname AzureToken
#' @export
AzureTokenManaged <- R6::R6Class("AzureTokenManaged", inherit=AzureToken,

public=list(

    initialize=function(resource, aad_host, token_args, use_cache)
    {
        self$auth_type <- "managed"
        super$initialize(resource, tenant="common", aad_host=aad_host, token_args=token_args, use_cache=use_cache)
    }
),

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


#' @rdname AzureToken
#' @export
AzureTokenCLI <- R6::R6Class("AzureTokenCLI",
    inherit = AzureToken,
    public = list(
        initialize = function(common_args)
        {
            self$auth_type <- "cli"
            do.call(super$initialize, common_args)
        }
    ),
    private = list(
        initfunc = function(init_args)
        {
            tryCatch(
                {
                    cmd <- build_access_token_cmd(resource = self$resource,
                                                  tenant = self$tenant)
                    result <- do.call(system2, append(cmd, list(stdout = TRUE)))
                    # result is a multi-line JSON string, concatenate together
                    paste0(result)
                },
                warning = function(cond)
                {
                    not_found <- grepl("not found", cond, fixed = TRUE)
                    not_loggedin <- grepl("az login", cond, fixed = TRUE) |
                        grepl("az account set", cond, fixed = TRUE)
                    bad_resource <- grepl(
                        "was not found in the tenant",
                        cond,
                        fixed = TRUE
                    )
                    if (not_found)
                        message("Azure CLI not found on path.")
                    else if (not_loggedin)
                        message("Please run 'az login' to set up account.")
                    else
                        message("Failed to invoke the Azure CLI.")
                }
            )
        },
        process_response = function(res)
        {
            # Parse the JSON from the CLI and fix the names to snake_case
            message(res)
            ret <- jsonlite::parse_json(res)
            list(
                token_type = ret$tokenType,
                access_token = ret$accessToken,
                expires_on = as.numeric(as.POSIXct(ret$expiresOn)),
                resource = self$resource
            )
        }
    )
)


norenew_alert <- function(version)
{
    if(version == 1)
        message("Server did not provide a refresh token: please reauthenticate to refresh.")
    else message("Server did not provide a refresh token: you will have to reauthenticate to refresh.\n",
                "Add the 'offline_access' scope to obtain a refresh token.")
}
