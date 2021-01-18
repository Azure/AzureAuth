context("v1.0 token other")

tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
username <- Sys.getenv("AZ_TEST_USERNAME")
password <- Sys.getenv("AZ_TEST_PASSWORD")
native_app <- Sys.getenv("AZ_TEST_NATIVE_APP_ID")
cert_app <- Sys.getenv("AZ_TEST_CERT_APP_ID")
cert_file <- Sys.getenv("AZ_TEST_CERT_FILE")
web_app <- Sys.getenv("AZ_TEST_WEB_APP_ID")
web_app_pwd <- Sys.getenv("AZ_TEST_WEB_APP_PASSWORD")
userpwd <- Sys.getenv("AZ_TEST_USERPWD")
admin_username <- Sys.getenv("AZ_TEST_ADMINUSERNAME")

if(tenant == "" || app == "" || username == "" || password == "" || native_app == "" ||
   cert_app == "" || cert_file == "" || web_app == "" || web_app_pwd == "" || userpwd == "")
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

suppressWarnings(file.remove(dir(AzureR_dir(), full.names=TRUE)))


test_that("Providing optional args works",
{
    res <- "https://management.azure.com/"

    # login hint
    aut_tok <- get_azure_token(res, tenant, native_app, username=admin_username, auth_type="authorization_code")
    expect_true(is_azure_token(aut_tok))
    expect_identical(res, decode_jwt(aut_tok)$payload$aud)

    expect_null(
        delete_azure_token(res, tenant, native_app, username=admin_username, auth_type="authorization_code",
                           confirm=FALSE))
})


test_that("Providing path in aad_host works",
{
    res <- "https://management.azure.com/"
    aad_url <- file.path("https://login.microsoftonline.com", normalize_tenant(tenant), "oauth2")

    tok <- get_azure_token(res, tenant, app, password=password, aad_host=aad_url)
    expect_true(is_azure_token(tok))
    expect_identical(res, decode_jwt(tok)$payload$aud)
})


test_that("On-behalf-of flow works",
{
    tok0 <- get_azure_token(app, tenant, native_app)
    expect_true(is_azure_token(tok0))

    name0 <- decode_jwt(tok0)$payload$name
    expect_type(name0, "character")

    tok1 <- get_azure_token("https://graph.microsoft.com/", tenant, app, password, on_behalf_of=tok0)
    expect_true(is_azure_token(tok1))
    expect_identical("https://graph.microsoft.com/", decode_jwt(tok1)$payload$aud)

    name1 <- decode_jwt(tok1)$payload$name
    expect_identical(name0, name1)

    expect_silent(tok1$refresh())
})


test_that("Certificate authentication works",
{
    res <- "https://management.azure.com/"
    tok <- get_azure_token(res, tenant, cert_app, certificate=cert_file)
    expect_true(is_azure_token(tok))
    expect_identical(res, decode_jwt(tok)$payload$aud)
})


test_that("Standalone auth works",
{
    res <- "https://management.azure.com/"

    auth_uri <- build_authorization_uri(res, tenant, native_app)
    code <- AzureAuth:::listen_for_authcode(auth_uri, "http://localhost:1410")
    tok <- get_azure_token(res, tenant, native_app, auth_code=code, use_cache=FALSE)
    expect_identical(tok$hash(), aut_hash)
    expect_identical(res, decode_jwt(tok)$payload$aud)

    creds <- get_device_creds(res, tenant, native_app)
    cat(creds$message, "\n")
    tok2 <- get_azure_token(res, tenant, native_app, auth_type="device_code", device_creds=creds, use_cache=FALSE)
    expect_identical(tok2$hash(), dev_hash)
    expect_identical(res, decode_jwt(tok2)$payload$aud)
})


test_that("Webapp authentication works",
{
    res <- "https://management.azure.com/"

    tok <- get_azure_token(res, tenant, web_app, password=web_app_pwd, auth_type="authorization_code")
    expect_true(is_azure_token(tok))
    expect_identical(res, decode_jwt(tok)$payload$aud)

    tok2 <- get_azure_token(res, tenant, web_app, password=web_app_pwd)  # client credentials
    expect_true(is_azure_token(tok2))
    expect_identical(tok2$auth_type, "client_credentials")
    expect_identical(res, decode_jwt(tok2)$payload$aud)

    tok3 <- get_azure_token(res, tenant, web_app, password=web_app_pwd, username=admin_username,
        auth_type="authorization_code")
    expect_true(is_azure_token(tok2))
    expect_identical(res, decode_jwt(tok3)$payload$aud)

    # web app expects client secret
    expect_error(get_azure_token(res, tenant, web_app))
})


test_that("Resource owner grant works",
{
    res <- "https://management.azure.com/"

    tok <- get_azure_token(res, tenant, native_app, password=userpwd, username=username, auth_type="resource_owner")
    expect_true(is_azure_token(tok))
})


test_that("Refreshing with changed resource works",
{
    res <- "https://management.azure.com/"

    tok <- get_azure_token(res, tenant, native_app)
    expect_identical(res, decode_jwt(tok)$payload$aud)

    tok$resource <- "https://graph.microsoft.com/"
    tok$refresh()
    expect_identical("https://graph.microsoft.com/", decode_jwt(tok)$payload$aud)
})
