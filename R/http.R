call_aad <- function(req)
{
    req %>%
        httr2::req_error(body=get_aad_error) %>%
        httr2::req_perform() %>%
        httr2::resp_body_json()
}


req_post_form <- function(url, body)
{
    httr2::request(url) %>%
        httr2::req_body_form(body)
}


get_aad_error <- function(res)
{
    status <- httr2::resp_status(res)
    if(status >= 300)
    {
        cont <- httr2::resp_body_json(res)

        if(is.character(cont))
            cont
        else if(is.list(cont) && is.character(cont$error_description))
            cont$error_description
        else ""
    }
    else ""
}


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
