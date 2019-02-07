#' @export
AzureToken <- R6::R6Class("AzureToken",

public=list(

    version=NULL,
    aad_host=NULL,
    tenant=NULL,
    auth_type=NULL,
    client=NULL,
    resource=NULL,
    scope=NULL,
    authorize_args=NULL,
    token_args=NULL,
    credentials=list(), # returned token details from host

    initialize=function(resource, tenant, app, password=NULL, username=NULL, certificate=NULL, auth_type=NULL,
                        aad_host="https://login.microsoftonline.com/", version=1,
                        authorize_args=list(), token_args=list())
    {
        self$version <- normalize_aad_version(version)
        self$aad_host <- aad_host
        self$tenant <- normalize_tenant(tenant)
        self$auth_type <- select_auth_type(password, username, certificate, auth_type)

        self$client <- aad_request_credentials(app, password, username, certificate, self$auth_type)

        self$authorize_args <- authorize_args
        self$token_args <- token_args

        if(self$version == 1)
            self$resource <- resource
        else self$scope <- resource

        # v2.0 endpoint doesn't provide an expires_on field, set it here
        self$credentials$expires_on <- as.character(floor(as.numeric(Sys.time())))

        private$initfunc <- switch(self$auth_type,
            authorization_code=init_authcode,
            device_code=init_devcode,
            client_credentials=init_clientcred,
            resource_owner=init_resowner
        )
        environment(private$initfunc) <- parent.env(environment())

        res <- private$initfunc()
        creds <- process_aad_response(res)

        self$credentials <- utils::modifyList(self$credentials, creds)
        self
    },

    cache=function()
    {},

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
        self$credentials$expires_on <- as.character(floor(as.numeric(Sys.time())))

        res <- if(!is.null(self$credentials$refresh_token))
        {
            body <- utils::modifyList(self$client,
                list(grant_type="refresh_token", refresh_token=self$credentials$refresh_token))
            body <- private$add_resource()

            uri <- aad_endpoint(self$aad_host, self$tenant, self$version, "token")
            httr::POST(uri, body=body, encode="form")

        }
        else private$initfunc() # reauthenticate if no refresh token

        creds <- try(process_httr_response(res))
        if(inherits(creds, "try-error"))
        {
            delete_azure_token(hash=self$hash(), confirm=FALSE)
            stop("Unable to refresh token", call.=FALSE)
        }

        self$credentials <- utils::modifyList(self$credentials, creds)
        self
    },

    add_resource <- function(body=self$client)
    {
        if(self$version == 1)
            c(body, self$resource)
        else c(body, self$scope)
    }
),

private=list(

    initialized=NULL,

    initfunc=NULL # will be filled in by initialize()
))


init_authcode <- function()
{

}


init_devcode <- function()
{
    # contact devicecode endpoint to get code
    dev_uri <- aad_endpoint(self$aad_host, self$tenant, self$version, "devicecode")
    body <- private$add_resource(list(client_id=self$client$client_id))
    
    res <- httr::POST(dev_uri, body=body, encode="form")
    creds <- process_aad_response(res)

    # tell user to enter the code
    cat(creds$message, "\n")

    # poll token endpoint for token
    access_uri <- aad_endpoint(self$aad_host, self$tenant, self$version, "token")
    body <- c(self$client, code=creds$device_code)

    message("Waiting for device code in browser...\nPress Esc/Ctrl + C to abort")
    interval <- as.numeric(creds$interval)
    ntries <- as.numeric(creds$expires_in) %/% interval
    for(i in seq_len(ntries))
    {
        Sys.sleep(interval)

        res <- httr::POST(access_uri, body=body, encode="form")

        status <- httr::status_code(res)
        cont <- httr::content(res)
        if(status == 400 && cont$error == "authorization_pending")
        {
            # do nothing
        }
        else if(status >= 300)
            process_aad_response(res) # fail here on error
        else break
    }
    if(status >= 300)
        stop("Unable to authenticate")

    message("Authentication complete.")
    res
}


init_clientcred <- function()
{
    # contact token endpoint directly with client credentials
    uri <- aad_endpoint(self$aad_host, self$tenant, self$version, "token")
    body <- private$add_resource()

    httr::POST(uri, body=body, encode="form")
}


init_resowner <- function()
{
    # contact token endpoint directly with resource owner username/password
    uri <- aad_endpoint(self$aad_host, self$tenant, self$version, "token")
    body <- private$add_resource()

    httr::POST(uri, body=body, encode="form")
}


aad_request_credentials <- function(app, password, username, certificate, auth_type)
{
    obj <- list(client_id=app, grant_type=auth_type)

    if(auth_type == "resource_owner")
    {
        if(is.null(username) && is.null(password))
            stop("Must provide a username and password for resource_owner grant", call.=FALSE)
        obj$grant_type <- "password"
        obj$username <- username
        obj$password <- password
    }
    else if(auth_type == "client_credentials")
    {
        if(!is.null(password))
            obj$client_secret <- password
        else if(!is.null(certificate))
        {
            obj$client_assertion_type <- "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            obj$client_assertion <- certificate
        }
        else stop("Must provide either a client secret or certificate for client_credentials grant", call.=FALSE)
    }
    else if(auth_type == "authorization_code")
    {
        if(!is.null(username))
            obj$login_hint <- username
    }

    obj
}


aad_endpoint <- function(aad_host, tenant, version=1, type=c("authorize", "token", "devicecode"))
{
    type <- match.arg(type)
    tenant <- normalize_tenant(tenant)

    uri <- httr::parse_url(aad_host)
    uri$path <- if(version == 1)
        file.path(tenant, "oauth2", type)
    else file.path(tenant, "oauth2/v2.0", type)

    httr::build_url(uri)
}


normalize_aad_version <- function(v)
{
    if(v == "1.0")
        v <- 1
    else if(v == "2.0")
        v <- 2
    if(!(is.numeric(v) && v %in% c(1, 2)))
        stop("Invalid AAD version")
    v
}


process_aad_response=function(res)
{
    status <- httr::status_code(res)
    if(status >= 300)
    {
        cont <- httr::content(res)

        msg <- if(is.character(cont))
            cont
        else if(is.list(cont) && is.character(cont$error_description))
            cont$error_description
        else ""

        msg <- paste0("obtain Azure Active Directory token. Message:\n", sub("\\.$", "", msg))
        list(token=httr::stop_for_status(status, msg))
    }
    else httr::content(res)
}
