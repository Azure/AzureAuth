# back-compatibility hacks for httr2
parse_url <- function(url)
{
    url <- httr2::url_parse(url)
    if(is_empty(url$path) || url$path == "/")
        url$path <- ""
    url
}

build_url <- function(url)
{
    if(!is_empty(url$path) && substr(url$path, 1, 1) != "/")
        url$path <- paste0("/", url$path)
    httr2::url_build(url)
}


# forward-compatibility hacks for AAD v1
as_httr2_token <- function(credentials, .date=Sys.time())
{
    if(!is_empty(credentials$expires_in))
        credentials$expires_in <- as.numeric(credentials$expires_in)

    if(is_empty(credentials$expires_in) && !is_empty(credentials$ext_expires_in))
        credentials$expires_in <- credentials$ext_expires_in

    credentials <- rlang::exec(httr2::oauth_token, !!!credentials, .date=.date)

    if(is_empty(credentials$expires_at) && !is_empty(credentials$expires_on))
        credentials$expires_at <- as.numeric(credentials$expires_on)

    if(is_empty(credentials$expires_at))
        stop("Unable to set expiry time", call.=FALSE)
    credentials
}

fix_v1_cached_creds <- function(credentials)
{
    if(!is_empty(credentials$expires_at))
        return(credentials)

    if(!is_empty(credentials$expires_on))
        credentials$expires_at <- as.numeric(credentials$expires_on)
    credentials
}

