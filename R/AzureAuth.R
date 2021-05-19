utils::globalVariables(c("self", "private"))


.onLoad <- function(libname, pkgname)
{
    make_AzureR_dir()
    options(azure_imds_version="2018-02-01")
    invisible(NULL)
}


# create a directory for saving creds -- ask first, to satisfy CRAN requirements
make_AzureR_dir <- function()
{
    AzureR_dir <- AzureR_dir()
    if(!dir.exists(AzureR_dir) && interactive())
    {
        ok <- get_confirmation(paste0(
            "The AzureR packages can save your authentication credentials in the directory:\n\n",
            AzureR_dir, "\n\n",
            "This saves you having to re-authenticate with Azure in future sessions. Create this directory?"))
        if(!ok)
            return(invisible(NULL))

        dir.create(AzureR_dir, recursive=TRUE)
    }
}


#' Data directory for AzureR packages
#'
#' @details
#' AzureAuth can save your authentication credentials in a user-specific directory, using the rappdirs package. On recent Windows versions, this will usually be in the location `C:\\Users\\(username)\\AppData\\Local\\AzureR`. On Unix/Linux, it will be in `~/.local/share/AzureR`, and on MacOS, it will be in `~/Library/Application Support/AzureR`.Alternatively, you can specify the location of the directory in the environment variable `R_AZURE_DATA_DIR`. AzureAuth does not modify R's working directory, which significantly lessens the risk of accidentally introducing cached tokens into source control.
#'
#' On package startup, if this directory does not exist, AzureAuth will prompt you for permission to create it. It's recommended that you allow the directory to be created, as otherwise you will have to reauthenticate with Azure every time. Note that many cloud engineering tools, including the [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest), save authentication credentials in this way. The prompt only appears in an interactive session (in the sense that `interactive()` returns TRUE); if AzureAuth is loaded in a batch script, the directory is not created if it doesn't already exist.
#'
#' `create_AzureR_dir` is a utility function to create the caching directory manually. This can be useful not just for non-interactive sessions, but also Jupyter and R notebooks, which are not _technically_ interactive in that `interactive()` returns FALSE.
#'
#' The caching directory is also used by other AzureR packages, notably AzureRMR (for storing Resource Manager logins) and AzureGraph (for Microsoft Graph logins). You should not save your own files in it; instead, treat it as something internal to the AzureR packages.
#'
#' @return
#' A string containing the data directory.
#'
#' @seealso
#' [get_azure_token]
#'
#' [rappdirs::user_data_dir]
#'
#' @rdname AzureR_dir
#' @export
AzureR_dir <- function()
{
    userdir <- Sys.getenv("R_AZURE_DATA_DIR")
    if(userdir != "")
        return(userdir)
    rappdirs::user_data_dir(appname="AzureR", appauthor="", roaming=FALSE)
}


#' @rdname AzureR_dir
#' @export
create_AzureR_dir <- function()
{
    azdir <- AzureR_dir()
    if(!dir.exists(azdir))
        dir.create(azdir, recursive=TRUE)
}
