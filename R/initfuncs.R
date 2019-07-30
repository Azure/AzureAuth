init_authcode <- function(init_args)
{
    stopifnot(is.list(self$token_args))
    stopifnot(is.list(self$authorize_args))

    opts <- utils::modifyList(list(
        resource=if(self$version == 1) self$resource else self$scope,
        tenant=self$tenant,
        app=self$client$client_id,
        password=self$client$client_secret,
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

    httr::POST(access_uri, body=body, encode="form")
}


init_devcode <- function(init_args)
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

    poll_for_token(access_uri, body, creds$interval, creds$expires_in)
}


init_clientcred <- function(init_args)
{
    # contact token endpoint directly with client credentials
    uri <- private$aad_uri("token")
    body <- private$build_access_body()

    httr::POST(uri, body=body, encode="form")
}


init_resowner <- function(init_args)
{
    # contact token endpoint directly with resource owner username/password
    uri <- private$aad_uri("token")
    body <- private$build_access_body()

    httr::POST(uri, body=body, encode="form")
}


init_managed <- function(init_args)
{
    stopifnot(is.list(self$token_args))

    uri <- private$aad_uri("token")
    query <- utils::modifyList(self$token_args,
        list(`api-version`=getOption("azure_imds_version"), resource=self$resource))

    secret <- Sys.getenv("MSI_SECRET")
    headers <- if(secret == "")
        httr::add_headers(secret=secret)
    else httr::add_headers(metadata="true")

    httr::GET(uri, headers, query=query)
}


listen_for_authcode <- function(remote_url, local_url)
{
    local_url <- httr::parse_url(local_url)
    localhost <- if(local_url$hostname == "localhost") "127.0.0.1" else local_url$hostname
    localport <- local_url$port

    # based on httr::oauth_listener
    info <- NULL
    listen <- function(env)
    {
        query <- env$QUERY_STRING
        info <<- if(is.character(query) && nchar(query) > 0)
            httr::parse_url(query)$query
        else list()

        if(is_empty(info$code))
            list(status=404L, headers=list(`Content-Type`="text/plain"), body="Not found")
        else list(status=200L, headers=list(`Content-Type`="text/plain"),
            body="Authenticated with Azure Active Directory. Please close this page and return to R.")
    }

    server <- httpuv::startServer(as.character(localhost), as.integer(localport), list(call=listen))
    on.exit(httpuv::stopServer(server))

    message("Waiting for authentication in browser...\nPress Esc/Ctrl + C to abort")
    httr::BROWSE(remote_url)

    while(is.null(info))
    {
        httpuv::service()
        Sys.sleep(0.001)
    }
    httpuv::service()

    if(is_empty(info$code))
    {
        msg <- gsub("\\+", " ", utils::URLdecode(info$error_description))
        stop("Authentication failed. Message:\n", msg, call.=FALSE)
    }

    message("Authentication complete.")
    info$code
}


poll_for_token <- function(url, body, interval, period)
{
    interval <- as.numeric(interval)
    ntries <- as.numeric(period) %/% interval

    message("Waiting for device code in browser...\nPress Esc/Ctrl + C to abort")
    for(i in seq_len(ntries))
    {
        Sys.sleep(interval)

        res <- httr::POST(url, body=body, encode="form")

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
        stop("Authentication failed.", call.=FALSE)

    message("Authentication complete.")
    res
}

