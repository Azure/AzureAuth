context("v2.0 token")

tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
username <- Sys.getenv("AZ_TEST_USERNAME")
password <- Sys.getenv("AZ_TEST_PASSWORD")
native_app <- Sys.getenv("AZ_TEST_NATIVE_APP_ID")

if(tenant == "" || app == "" || username == "" || password == "" || native_app == "")
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

    # obtain new tokens
    aut_tok <- get_azure_token(res, tenant, native_app, auth_type="authorization_code", version=2)
    expect_true(is_azure_token(aut_tok))
    expect_identical(aut_tok$hash(), aut_hash)

    ccd_tok <- get_azure_token(res, tenant, app, password=password, version=2)
    expect_true(is_azure_token(ccd_tok))
    expect_identical(ccd_tok$hash(), ccd_hash)

    dev_tok <- get_azure_token(res, tenant, native_app, auth_type="device_code", version=2)
    expect_true(is_azure_token(dev_tok))
    expect_identical(dev_tok$hash(), dev_hash)

    aut_expire <- as.numeric(aut_tok$credentials$expires_on)
    ccd_expire <- as.numeric(ccd_tok$credentials$expires_on)
    dev_expire <- as.numeric(dev_tok$credentials$expires_on)

    Sys.sleep(2)

    # refresh (will have to reauthenticate for authcode and devcode)
    aut_tok$refresh()
    ccd_tok$refresh()
    dev_tok$refresh()

    expect_true(as.numeric(aut_tok$credentials$expires_on) > aut_expire)
    expect_true(as.numeric(ccd_tok$credentials$expires_on) > ccd_expire)
    expect_true(as.numeric(dev_tok$credentials$expires_on) > dev_expire)

    expect_null(delete_azure_token(res, tenant, native_app, auth_type="authorization_code", version=2, confirm=FALSE))
    expect_null(delete_azure_token(res, tenant, app, password=password, version=2, confirm=FALSE))
    expect_null(delete_azure_token(res, tenant, native_app, auth_type="device_code", version=2, confirm=FALSE))
})


# should only get 1 authcode and 1 devcode prompt here
test_that("v2.0 refresh with offline scope works",
{
    res <- "https://management.azure.com/.default"
    res2 <- "offline_access"

    aut_tok <- get_azure_token(c(res, res2), tenant, native_app, auth_type="authorization_code", version=2)
    expect_true(!is_empty(aut_tok$credentials$refresh_token))

    dev_tok <- get_azure_token(c(res, res2), tenant, native_app, auth_type="device_code", version=2)
    expect_true(!is_empty(dev_tok$credentials$refresh_token))

    aut_expire <- as.numeric(aut_tok$credentials$expires_on)
    dev_expire <- as.numeric(dev_tok$credentials$expires_on)

    Sys.sleep(2)

    # refresh (should not have to reauthenticate)
    aut_tok$refresh()
    dev_tok$refresh()

    expect_true(as.numeric(aut_tok$credentials$expires_on) > aut_expire)
    expect_true(as.numeric(dev_tok$credentials$expires_on) > dev_expire)

    # load cached tokens: should not get repeated login prompts/screens
    aut_tok2 <- get_azure_token(c(res, res2), tenant, native_app, auth_type="authorization_code", version=2)
    expect_true(is_azure_token(aut_tok2))

    dev_tok2 <- get_azure_token(c(res, res2), tenant, native_app, auth_type="device_code", version=2)
    expect_true(is_azure_token(dev_tok2))

    expect_null(
        delete_azure_token(c(res, res2), tenant, native_app, auth_type="authorization_code", version=2, confirm=FALSE))
    expect_null(delete_azure_token(c(res, res2), tenant, native_app, auth_type="device_code", version=2, confirm=FALSE))
})


# should get 1 authcode screen here
test_that("Providing optional args works",
{
    res <- "https://management.azure.com/.default"

    aut_tok <- get_azure_token(res, tenant, native_app, username=username, auth_type="authorization_code", version=2)
    expect_true(is_azure_token(aut_tok))

    # cannot provide both username and pwd with authcode
    expect_error(
        get_azure_token(res, tenant, native_app, password=password, username=username, auth_type="authorization_code",
            version=2))

    expect_null(
        delete_azure_token(res, tenant, native_app, username=username, auth_type="authorization_code", version=2,
            confirm=FALSE))
})


test_that("Dubious requests handled gracefully",
{
    badres <- "resource"
    expect_error(get_azure_token(badres, tenant, app, password=password, version=2))

    nopath <- "https://management.azure.com"
    expect_warning(tok <- get_azure_token(nopath, tenant, app, password=password, version=2))
    expect_equal(tok$scope, "https://management.azure.com/.default")
})


test_that("Providing path in aad_host works",
{
    res <- "https://management.azure.com/.default"
    aad_url <- file.path("https://login.microsoftonline.com", normalize_tenant(tenant), "oauth2/v2.0")

    tok <- get_azure_token(res, tenant, app, password=password, aad_host=aad_url, version=2)
    expect_true(is_azure_token(tok))
})


test_that("On-behalf-of flow works",
{
    res <- file.path(app, ".default")
    res2 <- "offline_access"

    tok0 <- get_azure_token(c(res, res2), tenant, native_app, version=2)
    expect_true(is_azure_token(tok0))

    name0 <- decode_jwt(tok0$credentials$access_token)$payload$name
    expect_type(name0, "character")

    tok1 <- get_azure_token("https://graph.microsoft.com/.default", tenant, app, password, on_behalf_of=tok0, version=2)
    expect_true(is_azure_token(tok1))

    name1 <- decode_jwt(tok1$credentials$access_token)$payload$name
    expect_identical(name0, name1)

    expect_silent(tok1$refresh())
})
