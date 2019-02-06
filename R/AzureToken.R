#' Azure OAuth authentication
#'
#' Azure OAuth 2.0 token class, inheriting from the [Token2.0 class][httr::Token2.0] in httr. Rather than calling the initialization method directly, tokens should be created via [get_azure_token()].
#'
#' @docType class
#' @section Methods:
#' - `refresh`: Refreshes the token. For expired Azure tokens using client credentials, refreshing really means requesting a new token.
#' - `validate`: Checks if the token is still valid. For Azure tokens using client credentials, this just checks if the current time is less than the token's expiry time.
#' - `hash`: Computes an MD5 hash on selected fields of the token. Used internally for identification purposes when caching.
#' - `cache`: Stores the token on disk for use in future sessions.
#'
#' @seealso
#' [get_azure_token], [httr::Token]
#'
#' @format An R6 object of class `AzureToken`.
#' @export
AzureToken <- R6::R6Class("AzureToken", inherit=httr::Token2.0,

public=list(

    # need to do hacky init to support explicit re-authentication instead of using a refresh token
    initialize=function(endpoint, app, user_params, use_device=FALSE, client_credentials=TRUE)
    {
        params <- list(scope=NULL, user_params=user_params, type=NULL, use_oob=FALSE, as_header=TRUE,
                       use_basic_auth=FALSE, config_init=list(),
                       client_credentials=client_credentials, use_device=use_device)

        # if this is an existing object, don't use cached value
        # avoids infinite loop when refresh() calls initialize()
        tokenfile <- file.path(AzureRMR_dir(), token_hash_internal(endpoint, app, params))
        if(file.exists(tokenfile) && !isTRUE(private$initialized))
        {
            message("Loading cached token")
            token <- readRDS(tokenfile)
            self$app <- token$app
            self$endpoint <- token$endpoint
            self$params <- token$params
            self$cache_path <- token$cache_path
            self$private_key <- token$private_key
            self$credentials <- token$credentials
            private$initialized <- TRUE
            return(self$refresh())
        }
        private$initialized <- TRUE

        # use httr initialize for authorization_code, client_credentials methods
        if(!use_device && is.null(user_params$username))
            return(super$initialize(app=app, endpoint=endpoint, params=params, cache_path=FALSE))

        self$app <- app
        self$endpoint <- endpoint
        self$params <- params
        self$cache_path <- NULL
        self$private_key <- NULL

        # use our own init functions for device_code, resource_owner methods
        if(use_device)
            private$init_with_device(user_params)
        else private$init_with_username(user_params)

        if(dir.exists(AzureRMR_dir()))
            saveRDS(self, tokenfile)

        self
    },

    # overrides httr::Token method
    hash=function()
    {
        token_hash_internal(self$endpoint, self$app, self$params)
    },

    # overrides httr::Token method
    cache=function()
    {
        if(dir.exists(AzureRMR_dir()))
        {
            filename <- file.path(AzureRMR_dir(), self$hash())
            saveRDS(self, filename)
        }
        invisible(NULL)
    },

    # overrides httr::Token2.0 method
    can_refresh=function()
    {
        TRUE  # always can refresh
    },

    # overrides httr::Token2.0 method
    validate=function()
    {
        if(!is.null(self$endpoint$validate))
            return(super$validate())

        expdate <- as.POSIXct(as.numeric(self$credentials$expires_on), origin="1970-01-01")
        curdate <- Sys.time()
        curdate < expdate
    },

    # overrides httr::Token2.0 method
    refresh=function()
    {
        # use a refresh token if it exists
        # don't call superclass method b/c of different caching logic
        if(!is.null(self$credentials$refresh_token))
        {
            body <- list(
                refresh_token=self$credentials$refresh_token,
                client_id=self$app$key,
                client_secret=self$app$secret,
                grant_type="refresh_token"
            )
            body <- modifyList(body, self$params$user_params)

            access_uri <- sub("devicecode$", "token", self$endpoint$access)
            res <- httr::POST(access_uri, body=body, encode="form")

            if(httr::status_code(res) >= 300)
            {
                delete_azure_token(hash=self$hash(), confirm=FALSE)
                stop("Unable to refresh", call.=FALSE)
            }
            self$credentials <- utils::modifyList(self$credentials, httr::content(res))
        }
        else # re-authenticate if no refresh token
        {
            # save the hash so we can delete the cached token on failure (initialize can modify state)
            hash <- self$hash()

            res <- try(self$initialize(self$endpoint, self$app, self$params$user_params,
                    use_device=self$params$use_device,
                    client_credentials=self$params$client_credentials), silent=TRUE)
            if(inherits(res, "try-error"))
            {
                delete_azure_token(hash=hash, confirm=FALSE)
                stop("Unable to reauthenticate", call.=FALSE)
            }
        }

        self$cache()
        self
    },

    print=function()
    {
        cat(format_auth_header(self))
        invisible(self)
    }
),

private=list(
    initialized=NULL,

    # device code authentication: after sending initial request, loop until server indicates code has been received
    # after init_oauth2.0, oauth2.0_access_token
    init_with_device=function(user_params)
    {
        # must be in an interactive session to use devicecode; should not affect cached tokens
        if(!interactive())
            stop("Must be in an interactive session to use device code authentication", call.=FALSE)

        creds <- httr::oauth2.0_access_token(self$endpoint, self$app, code=NULL, user_params=user_params,
            redirect_uri=NULL)

        cat(creds$message, "\n")  # tell user to enter the code

        req_params <- list(client_id=self$app$key, grant_type="device_code", code=creds$device_code)
        req_params <- utils::modifyList(user_params, req_params)
        access_uri <- sub("devicecode$", "token", self$endpoint$access)

        message("Waiting for device code in browser...\nPress Esc/Ctrl + C to abort")
        interval <- as.numeric(creds$interval)
        ntries <- as.numeric(creds$expires_in) %/% interval
        for(i in seq_len(ntries))
        {
            Sys.sleep(interval)

            res <- httr::POST(access_uri, httr::add_headers(`Cache-Control`="no-cache"), encode="form",
                              body=req_params)

            status <- httr::status_code(res)
            cont <- httr::content(res)
            if(status == 400 && cont$error == "authorization_pending")
            {
                # do nothing
            }
            else if(status >= 300)
                httr::stop_for_status(res)
            else break
        }
        if(status >= 300)
            stop("Unable to authenticate")

        message("Authentication complete.")
        self$credentials <- cont
        NULL
    },

    # resource owner authentication: send username/password
    init_with_username=function(user_params)
    {
        body <- list(
            resource=user_params$resource,
            client_id=self$app$key,
            grant_type="password",
            username=user_params$username,
            password=user_params$password)

        res <- httr::POST(self$endpoint$access, httr::add_headers(`Cache-Control`="no-cache"), encode="form",
                          body=body)

        httr::stop_for_status(res, task="get an access token")
        self$credentials <- httr::content(res)
        NULL
    }
))


