select_auth_type <- function(password, username, certificate, auth_type, on_behalf_of)
{
    if(!is.null(auth_type))
    {
        if(!auth_type %in%
           c("authorization_code", "device_code", "client_credentials",
             "resource_owner", "on_behalf_of", "managed", "cli"))
            stop("Invalid authentication method")
        return(auth_type)
    }

    got_pwd <- !is.null(password)
    got_user <- !is.null(username)
    got_cert <- !is.null(certificate)
    got_httpuv <- system.file(package="httpuv") != ""

    auth_type <- if(got_pwd && got_user && !got_cert)
        "resource_owner"
    else if(!got_pwd && !got_user && !got_cert)
    {
        if(!got_httpuv)
        {
            message("httpuv not installed, defaulting to device code authentication")
            "device_code"
        }
        else "authorization_code"
    }
    else if(!got_pwd && !got_cert && got_user && got_httpuv)
        "authorization_code"
    else if((got_pwd && !got_user) || got_cert)
    {
        if(is_empty(on_behalf_of))
            "client_credentials"
        else "on_behalf_of"
    }
    else stop("Can't select authentication method", call.=FALSE)

    message("Using ", auth_type, " flow")
    auth_type
}


process_aad_response <- function(res)
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

process_cli_response <- function(res, resource)
{
    # Parse the JSON from the CLI and fix the names to snake_case
    ret <- jsonlite::parse_json(res)
    tok_data <- list(
        token_type = ret$tokenType,
        access_token = ret$accessToken,
        expires_on = as.numeric(as.POSIXct(ret$expiresOn))
    )
    # CLI doesn't return resource identifier so we need to pass it through
    if (!missing(resource)) tok_data$resource <- resource
    return(tok_data)
}


# need to capture bad scopes before requesting auth code
# v2.0 endpoint will show error page rather than redirecting, causing get_azure_token to wait forever
verify_v2_scope <- function(scope)
{
    # some OpenID scopes get a pass
    openid_scopes <- c("openid", "email", "profile", "offline_access")
    if(scope %in% openid_scopes)
        return(scope)

    # but not all
    bad_scopes <- c("address", "phone")
    if(scope %in% bad_scopes)
        stop("Unsupported OpenID scope: ", scope, call.=FALSE)

    # is it a URI or GUID?
    valid_uri <- !is.null(httr::parse_url(scope)$scheme)
    valid_guid <- is_guid(sub("/.*$", "", scope))
    if(!valid_uri && !valid_guid)
        stop("Invalid scope (must be a URI or GUID): ", scope, call.=FALSE)

    # if a URI or GUID, check that there is a valid scope in the path
    if(valid_uri)
    {
        uri <- httr::parse_url(scope)
        if(uri$path == "")
        {
            warning("No path supplied for scope ", scope, "; setting to /.default", call.=FALSE)
            uri$path <- ".default"
            scope <- httr::build_url(uri)
        }
    }
    else
    {
        path <- sub("^[^/]+/?", "", scope)
        if(path == "")
        {
            warning("No path supplied for scope ", scope, "; setting to /.default", call.=FALSE)
            scope <- sub("//", "/", paste0(scope, "/.default"))
        }
    }
    scope
}


aad_uri <- function(aad_host, tenant, version, type, query=list())
{
    uri <- httr::parse_url(aad_host)
    uri$query <- query

    uri$path <- if(nchar(uri$path) == 0)
    {
        if(version == 1)
            file.path(tenant, "oauth2", type)
        else file.path(tenant, "oauth2/v2.0", type)
    }
    else file.path(uri$path, type)

    httr::build_url(uri)
}


paste_v2_scopes <- function(scope)
{
    paste(scope, collapse=" ")
}


# display confirmation prompt, return TRUE/FALSE (no NA)
get_confirmation <- function(msg, default=TRUE)
{
    ok <- if(getRversion() < numeric_version("3.5.0"))
    {
        msg <- paste(msg, if(default) "(Yes/no/cancel) " else "(yes/No/cancel) ")
        yn <- readline(msg)
        if(nchar(yn) == 0)
            default
        else tolower(substr(yn, 1, 1)) == "y"
    }
    else utils::askYesNo(msg, default)
    isTRUE(ok)
}


in_shiny <- function()
{
    ("shiny" %in% loadedNamespaces()) && shiny::isRunning()
}

build_az_token_cmd <- function(command = "az", resource, tenant)
{
    args <- c("account", "get-access-token", "--output json")
    if (!missing(resource)) args <- c(args, paste("--resource", resource))
    if (!missing(tenant)) args <- c(args, paste("--tenant", tenant))
    list(command = command, args = args)
}

handle_az_cmd_errors <- function(cond)
{
    not_loggedin <- grepl("az login", cond, fixed = TRUE) |
        grepl("az account set", cond, fixed = TRUE)
    not_found <- grepl("not found", cond, fixed = TRUE)
    error_in <- grepl("error in running", cond, fixed = TRUE)

    if (not_found | error_in)
    {
        msg <- paste("az is not installed or not in PATH.\n",
            "Please see: ",
            "https://learn.microsoft.com/en-us/cli/azure/install-azure-cli\n",
            "for installation instructions."
        )
        stop(msg)
    }
    else if (not_loggedin)
    {
        stop("You are not logged into the Azure CLI.
        Please call AzureAuth::az_login()
        or run 'az login' from your shell and try again.")
    }
    else
    {
        # Other misc errors, pass through the CLI error message
        message("Failed to invoke the Azure CLI.")
        stop(cond)
    }
}

capt <- function(...) {
    print(list(...))
    print("a" %in% list(...))
}

az_login <- function(command = "az",...)
{
    args <- list(...)
    cmdargs <- list(command = command, args = c("login"))
    for (arg in c("username", "password", "tenant", "scope",
                  "service_principal", "use_device_code")) {
        if (arg %in% names(args))
            cmdargs$args <- c(cmdargs$args, paste0("--", arg, " ", args[arg]))
    }
    cat("Trying to open a web browser to log into Azure CLI...\n")
    cat(cmdargs$command, paste(cmdargs$args), "\n")
    do.call(system2, cmdargs)
}

execute_az_token_cmd <- function(cmd)
{
    tryCatch(
        {
            result <- do.call(system2, append(cmd, list(stdout = TRUE)))
            # result is a multi-line JSON string, concatenate together
            paste0(result)
        },
        warning = function()
        {
            # if an error case, catch it, pass the error string and handle it
            handle_az_cmd_errors(result)
        },
        error = function(cond)
        {
            handle_az_cmd_errors(cond$message)
        }
    )
}