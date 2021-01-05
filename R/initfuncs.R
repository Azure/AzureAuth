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
    body$grant_type <- "urn:ietf:params:oauth:grant-type:device_code"

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

