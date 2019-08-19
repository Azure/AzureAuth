context("v1.0 token")

tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
username <- Sys.getenv("AZ_TEST_USERNAME")
password <- Sys.getenv("AZ_TEST_PASSWORD")
native_app <- Sys.getenv("AZ_TEST_NATIVE_APP_ID")
cert_app <- Sys.getenv("AZ_TEST_CERT_APP_ID")
cert_file <- Sys.getenv("AZ_TEST_CERT_FILE")
web_app <- Sys.getenv("AZ_TEST_WEB_APP_ID")
web_app_pwd <- Sys.getenv("AZ_TEST_WEB_APP_PASSWORD")

if(tenant == "" || app == "" || username == "" || password == "" || native_app == "" ||
   cert_app == "" || cert_file == "" || web_app == "" || web_app_pwd == "")
    skip("Authentication tests skipped: ARM credentials not set")

aut_hash <- Sys.getenv("AZ_TEST_AUT_HASH")
ccd_hash <- Sys.getenv("AZ_TEST_CCD_HASH")
dev_hash <- Sys.getenv("AZ_TEST_DEV_HASH")

if(aut_hash == "" || ccd_hash == "" || dev_hash == "")
    skip("Authentication tests skipped: token hashes not set")

if(system.file(package="httpuv") == "")
    skip("Authentication tests skipped: httpuv must be installed")

# not a perfect test: will fail to detect Linux DSVM issue
if(!interactive())
    skip("Authentication tests skipped: must be an interactive session")

test_that("v1.0 simple authentication works",
{
    suppressWarnings(file.remove(dir(AzureR_dir(), full.names=TRUE)))

    res <- "https://management.azure.com/"

    # obtain new tokens
    aut_tok <- get_azure_token(res, tenant, native_app, auth_type="authorization_code")
    expect_true(is_azure_token(aut_tok))
    expect_identical(aut_tok$hash(), aut_hash)

    ccd_tok <- get_azure_token(res, tenant, app, password=password)
    expect_true(is_azure_token(ccd_tok))
    expect_identical(ccd_tok$hash(), ccd_hash)

    dev_tok <- get_azure_token(res, tenant, native_app, auth_type="device_code")
    expect_true(is_azure_token(dev_tok))
    expect_identical(dev_tok$hash(), dev_hash)

    aut_expire <- as.numeric(aut_tok$credentials$expires_on)
    ccd_expire <- as.numeric(ccd_tok$credentials$expires_on)
    dev_expire <- as.numeric(dev_tok$credentials$expires_on)

    Sys.sleep(2)

    # refresh/reauthenticate
    aut_tok$refresh()
    ccd_tok$refresh()
    dev_tok$refresh()

    expect_true(as.numeric(aut_tok$credentials$expires_on) > aut_expire)
    expect_true(as.numeric(ccd_tok$credentials$expires_on) > ccd_expire)
    expect_true(as.numeric(dev_tok$credentials$expires_on) > dev_expire)

    # load cached tokens: should not get repeated login prompts/screens
    aut_tok2 <- get_azure_token(res, tenant, native_app, auth_type="authorization_code")
    expect_true(is_azure_token(aut_tok2))
    expect_identical(aut_tok2$hash(), aut_hash)

    ccd_tok2 <- get_azure_token(res, tenant, app, password=password)
    expect_true(is_azure_token(ccd_tok2))
    expect_identical(ccd_tok2$hash(), ccd_hash)

    dev_tok2 <- get_azure_token(res, tenant, native_app, auth_type="device_code")
    expect_true(is_azure_token(dev_tok2))
    expect_identical(dev_tok2$hash(), dev_hash)

    # resource must be a single string
    expect_error(get_azure_token(c("res", "openid"), tenant, native_app))

    expect_null(delete_azure_token(res, tenant, native_app, auth_type="authorization_code", confirm=FALSE))
    expect_null(delete_azure_token(res, tenant, app, password=password, confirm=FALSE))
    expect_null(delete_azure_token(res, tenant, native_app, auth_type="device_code", confirm=FALSE))
})

