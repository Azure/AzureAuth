init_authcode <- function()
{
    stopifnot(is.list(self$token_args))

    if(!requireNamespace("httpuv", quietly=TRUE))
        stop("httpuv package must be installed to use authorization_code method", call.=FALSE)

    # browse to authorization endpoint to get code
    auth_uri <- httr::parse_url(private$aad_endpoint("authorize"))

    opts <- utils::modifyList(list(
        client_id=self$client$client_id,
        response_type="code",
        redirect_uri="http://localhost:1410/",
        resource=self$resource,
        scope=paste(self$scope, collapse=" "),
        client_secret=self$client$client_secret,
        login_hint=self$client$login_hint,
        state=paste0(sample(letters, 20, TRUE), collapse="") # random nonce
    ), self$authorize_args)

    auth_uri$query <- opts
    redirect <- httr::parse_url(opts$redirect_uri)
    host <- if(redirect$hostname == "localhost") "127.0.0.1" else redirect$hostname
    code <- listen_for_authcode(auth_uri, host, redirect$port)

    # contact token endpoint for token
    access_uri <- private$aad_endpoint("token")
    body <- c(self$client, code=code, redirect_uri=opts$redirect_uri, self$token_args)

    httr::POST(access_uri, body=body, encode="form")
}


init_devcode <- function()
{
    # contact devicecode endpoint to get code
    dev_uri <- private$aad_endpoint("devicecode")
    body <- private$build_access_body(list(client_id=self$client$client_id))
    
    res <- httr::POST(dev_uri, body=body, encode="form")
    creds <- process_aad_response(res)

    # tell user to enter the code
    cat(creds$message, "\n")

    # poll token endpoint for token
    access_uri <- private$aad_endpoint("token")
    body <- c(self$client, code=creds$device_code)

    poll_for_token(access_uri, body, creds$interval, creds$expires_in)
}


init_clientcred <- function()
{
    # contact token endpoint directly with client credentials
    uri <- private$aad_endpoint("token")
    body <- private$build_access_body()

    httr::POST(uri, body=body, encode="form")
}


init_resowner <- function()
{
    # contact token endpoint directly with resource owner username/password
    uri <- private$aad_endpoint("token")
    body <- private$build_access_body()

    httr::POST(uri, body=body, encode="form")
}


listen_for_authcode <- function(url, localhost="127.0.0.1", localport=1410)
{
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
    httr::BROWSE(url)

    while(is.null(info))
    {
        httpuv::service()
        Sys.sleep(0.001)
    }
    httpuv::service()

    if(is_empty(info$code))
    {
        msg <- gsub("\\+", " ", URLdecode(info$error_description))
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
