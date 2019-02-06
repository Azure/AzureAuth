#' @importFrom utils modifyList
NULL

.onLoad <- function(libname, pkgname)
{
    make_AzureAuth_dir()
    invisible(NULL)
}


# create a directory for saving creds -- ask first, to satisfy CRAN requirements
make_AzureAuth_dir <- function()
{
    AzureAuth_dir <- AzureAuth_dir()
    if(!dir.exists(AzureAuth_dir) && interactive())
    {
        yn <- readline(paste0(
                "AzureAuth can cache Azure Active Directory tokens in the directory:\n\n",
                AzureAuth_dir, "\n\n",
                "This saves you having to re-authenticate with Azure in future sessions. Create this directory? (Y/n) "))
        if(tolower(substr(yn, 1, 1)) == "n")
            return(invisible(NULL))

        dir.create(AzureAuth_dir, recursive=TRUE)
    }
}


#' Data directory for AzureAuth
#'
#' @details
#' AzureAuth can store authentication credentials and OAuth tokens in a user-specific directory, using the rappdirs package. On recent Windows versions, this will usually be in the location `C:\\Users\\(username)\\AppData\\Local\\AzureR\\AzureAuth`. On Unix/Linux, it will be in `~/.local/share/AzureAuth`, and on MacOS, it will be in `~/Library/Application Support/AzureAuth`. The working directory is not touched (which significantly lessens the risk of accidentally introducing cached tokens into source control).
#'
#' On package startup, if this directory does not exist, AzureAuth will prompt you for permission to create it. It's recommended that you allow the directory to be created, as otherwise you will have to reauthenticate with Azure every time. Note that many cloud engineering tools, including the [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest), save authentication credentials in this way.
#'
#' @return
#' A string containing the data directory.
#'
#' @seealso
#' [get_azure_token]
#'
#' [rappdirs::user_data_dir]
#'
#' @export
AzureAuth_dir <- function()
{
    rappdirs::user_data_dir(appname="AzureAuth", appauthor="AzureR", roaming=FALSE)
}
