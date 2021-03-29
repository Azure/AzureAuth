utils::globalVariables(c("self", "private"))


.onLoad <- function(libname, pkgname)
{
    make_AzureR_dir()
    options(azure_imds_version="2018-02-01")
    invisible(NULL)
}


# create a directory for saving creds -- print message if creating
make_AzureR_dir <- function()
{
    AzureR_dir <- AzureR_dir()
    if(!dir.exists(AzureR_dir))
    {
        packageStartupMessage("Saving Azure credentials in directory:\n", AzureR_dir)
        dir.create(AzureR_dir, recursive=TRUE)
    }
}


#' Data directory for AzureR packages
#'
#' @details
#' AzureAuth saves your authentication credentials in a user-specific directory, so you don't have to reauthenticate in every R session. The default location is determined using the rappdirs package: on recent Windows versions, this will usually be in the location `C:\\Users\\(username)\\AppData\\Local\\AzureR`; on Unix/Linux, it will be in `~/.local/share/AzureR`l and on MacOS, it will be in `~/Library/Application Support/AzureR`. Alternatively, you can specify the location of the directory in the environment variable `R_AZURE_DATA_DIR`. AzureAuth does not modify R's working directory, which significantly lessens the risk of accidentally introducing cached tokens into source control.
#'
#' This directory is also used by other AzureR packages, notably AzureRMR (for storing Resource Manager logins) and AzureGraph (for Microsoft Graph logins). You should not save your own files in it; instead, treat it as something internal to the AzureR packages.
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
    userdir <- Sys.getenv("R_AZURE_DATA_DIR")
    if(userdir != "")
        return(userdir)
    rappdirs::user_data_dir(appname="AzureR", appauthor="", roaming=FALSE)
}
