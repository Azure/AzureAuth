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
    credentials=NULL, # returned token details from host

    initialize=function(resource, tenant, app, password=NULL, username=NULL, certificate=NULL, auth_type=NULL,
                        aad_host="https://login.microsoftonline.com/", version=1,
                        authorize_args=list(), token_args=list())
    {
        self$version <- normalize_aad_version(version)
        self$aad_host <- aad_host
        self$tenant <- normalize_tenant(tenant)
        self$auth_type <- select_auth_type(password, username, certificate, auth_type)

        self$client <- request_credentials(app, password, username, certificate, self$auth_type)

        self$authorize_args=authorize_args
        self$token_args=token_args

        if(self$version == 1)
            self$resource <- resource
        else self$scope <- resource

        self$credentials <- switch(self$auth_type,
            authorization_code=private$init_authcode(),
            device_code=private$init_devcode(),
            client_credentials=private$init_clientcred(),
            resource_owner=self$init_resowner()
        )

        # v2.0 endpoint doesn't provide an expires_on field
        if(is_empty(self$credentials$expires_on))
            self$credentials$expires_on <- as.character(as.numeric(Sys.time()))

        self
    },

    cache=function()
    {},

    hash=function()
    {},

    validate=function()
    {},

    can_refresh=function()
    {
        TRUE
    },

    refresh=function()
    {}
),

private=list(

    initialized=NULL,

    init_authcode=function(){},

    init_devcode=function(){},

    init_clientcred=function()
    {
        # contact token endpoint directly with client credentials
        uri <- aad_endpoint(self$aad_host, self$tenant, self$version, "token")
        body <- if(self$version == 1)
            utils::modifyList(self$client, list(resource=self$resource))
        else utils::modifyList(self$client, list(scope=self$scope))

        res <- httr::POST(uri, body=body, encode="form")
        httr::content(res)
    },

    init_resowner=function(){}
))


request_credentials <- function(app, password, username, certificate, auth_type)
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
