context("v2.0 token")

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

aut_hash <- Sys.getenv("AZ_TEST_AUT_HASH2")
ccd_hash <- Sys.getenv("AZ_TEST_CCD_HASH2")
dev_hash <- Sys.getenv("AZ_TEST_DEV_HASH2")

if(aut_hash == "" || ccd_hash == "" || dev_hash == "")
    skip("Authentication tests skipped: token hashes not set")

if(system.file(package="httpuv") == "")
    skip("Authentication tests skipped: httpuv must be installed")

# not a perfect test: will fail to detect Linux DSVM issue
if(!interactive())
    skip("Authentication tests skipped: must be an interactive session")

# should get 2 authcode and 2 devcode prompts here
test_that("v2.0 simple authentication works",
{
    suppressWarnings(file.remove(dir(AzureR_dir(), full.names=TRUE)))

    res <- "https://management.azure.com/.default"
    resbase <- "https://management.azure.com"

    # obtain new tokens
    aut_tok <- get_azure_token(res, tenant, native_app, auth_type="authorization_code", version=2)
    expect_true(is_azure_token(aut_tok))
    expect_identical(aut_tok$hash(), aut_hash)
    expect_identical(resbase, decode_jwt(aut_tok)$payload$aud)

    ccd_tok <- get_azure_token(res, tenant, app, password=password, version=2)
    expect_true(is_azure_token(ccd_tok))
    expect_identical(ccd_tok$hash(), ccd_hash)
    expect_identical(resbase, decode_jwt(ccd_tok)$payload$aud)

    dev_tok <- get_azure_token(res, tenant, native_app, auth_type="device_code", version=2)
    expect_true(is_azure_token(dev_tok))
    expect_identical(dev_tok$hash(), dev_hash)
    expect_identical(resbase, decode_jwt(dev_tok)$payload$aud)

    aut_expire <- as.numeric(aut_tok$credentials$expires_at)
    ccd_expire <- as.numeric(ccd_tok$credentials$expires_at)
    dev_expire <- as.numeric(dev_tok$credentials$expires_at)

    Sys.sleep(2)

    # refresh (will have to reauthenticate for authcode and devcode)
    aut_tok$refresh()
    ccd_tok$refresh()
    dev_tok$refresh()

    expect_true(as.numeric(aut_tok$credentials$expires_at) > aut_expire)
    expect_true(as.numeric(ccd_tok$credentials$expires_at) > ccd_expire)
    expect_true(as.numeric(dev_tok$credentials$expires_at) > dev_expire)

    expect_null(delete_azure_token(res, tenant, native_app, auth_type="authorization_code", version=2, confirm=FALSE))
    expect_null(delete_azure_token(res, tenant, app, password=password, version=2, confirm=FALSE))
    expect_null(delete_azure_token(res, tenant, native_app, auth_type="device_code", version=2, confirm=FALSE))
})


# should only get 1 authcode and 1 devcode prompt here
test_that("v2.0 refresh with offline scope works",
{
    res <- "https://management.azure.com/.default"
    res2 <- "offline_access"
    resbase <- "https://management.azure.com"

    aut_tok <- get_azure_token(c(res, res2), tenant, native_app, auth_type="authorization_code", version=2)
    expect_true(!is_empty(aut_tok$credentials$refresh_token))
    expect_identical(resbase, decode_jwt(aut_tok)$payload$aud)

    dev_tok <- get_azure_token(c(res, res2), tenant, native_app, auth_type="device_code", version=2)
    expect_true(!is_empty(dev_tok$credentials$refresh_token))
    expect_identical(resbase, decode_jwt(dev_tok)$payload$aud)

    aut_expire <- as.numeric(aut_tok$credentials$expires_at)
    dev_expire <- as.numeric(dev_tok$credentials$expires_at)

    Sys.sleep(2)

    # refresh (should not have to reauthenticate)
    aut_tok$refresh()
    dev_tok$refresh()

    expect_true(as.numeric(aut_tok$credentials$expires_at) > aut_expire)
    expect_true(as.numeric(dev_tok$credentials$expires_at) > dev_expire)

    # load cached tokens: should not get repeated login prompts/screens
    aut_tok2 <- get_azure_token(c(res, res2), tenant, native_app, auth_type="authorization_code", version=2)
    expect_true(is_azure_token(aut_tok2))

    dev_tok2 <- get_azure_token(c(res, res2), tenant, native_app, auth_type="device_code", version=2)
    expect_true(is_azure_token(dev_tok2))

    expect_null(
        delete_azure_token(c(res, res2), tenant, native_app, auth_type="authorization_code", version=2, confirm=FALSE))
    expect_null(delete_azure_token(c(res, res2), tenant, native_app, auth_type="device_code", version=2, confirm=FALSE))
})

