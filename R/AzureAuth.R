#' @importFrom utils modifyList
NULL

.onLoad <- function(libname, pkgname)
{
    make_AzureR_dir()
    invisible(NULL)
}


# create a directory for saving creds -- ask first, to satisfy CRAN requirements
make_AzureR_dir <- function()
{
    AzureR_dir <- AzureR_dir()
    if(!dir.exists(AzureR_dir) && interactive())
    {
        yn <- readline(paste0(
                "AzureAuth can cache Azure Active Directory tokens in the directory:\n\n",
                AzureR_dir, "\n\n",
                "This saves you having to re-authenticate with Azure in future sessions. Create this directory? (Y/n) "))
        if(tolower(substr(yn, 1, 1)) == "n")
            return(invisible(NULL))

        dir.create(AzureR_dir, recursive=TRUE)
    }
}


#' Data directory for AzureR packages
#'
#' @details
#' AzureAuth can store authentication credentials and OAuth tokens in a user-specific directory, using the rappdirs package. On recent Windows versions, this will usually be in the location `C:\\Users\\(username)\\AppData\\Local\\AzureR`. On Unix/Linux, it will be in `~/.local/share/AzureR`, and on MacOS, it will be in `~/Library/Application Support/AzureR`. The working directory is not touched (which significantly lessens the risk of accidentally introducing cached tokens into source control).
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
AzureR_dir <- function()
{
    rappdirs::user_data_dir(appname="AzureR", appauthor="", roaming=FALSE)
}
