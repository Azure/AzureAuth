context("v2.0 token other")

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

suppressWarnings(file.remove(dir(AzureR_dir(), full.names=TRUE)))


# should get 1 authcode screen here
test_that("Providing optional args works",
{
    res <- "https://management.azure.com/.default"
    resbase <- "https://management.azure.com"

    aut_tok <- get_azure_token(res, tenant, native_app, username=admin_username, auth_type="authorization_code",
                               version=2)
    expect_true(is_azure_token(aut_tok))
    expect_identical(resbase, decode_jwt(aut_tok)$payload$aud)

    expect_null(
        delete_azure_token(res, tenant, native_app, username=admin_username, auth_type="authorization_code", version=2,
                           confirm=FALSE))
})


# should get a 'permissions requested' screen here
test_that("Providing multiple scopes works",
{
    scopes <- c(paste0("https://graph.microsoft.com/",
                     c("User.Read.All", "Directory.Read.All", "Directory.AccessAsUser.All")),
                "offline_access")

    aut_tok <- get_azure_token(scopes, tenant, native_app, auth_type="authorization_code", version=2)
    expect_true(is_azure_token(aut_tok))
    expect_identical("https://graph.microsoft.com", decode_jwt(aut_tok)$payload$aud)
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
    resbase <- "https://management.azure.com"

    tok <- get_azure_token(res, tenant, app, password=password, aad_host=aad_url, version=2)
    expect_true(is_azure_token(tok))
    expect_identical(resbase, decode_jwt(tok)$payload$aud)
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
    expect_identical("https://graph.microsoft.com", decode_jwt(tok1)$payload$aud)

    name1 <- decode_jwt(tok1$credentials$access_token)$payload$name
    expect_identical(name0, name1)

    expect_silent(tok1$refresh())
})


test_that("Certificate authentication works",
{
    res <- "https://management.azure.com/.default"
    resbase <- "https://management.azure.com"
    tok <- get_azure_token(res, tenant, cert_app, certificate=cert_file, version=2)
    expect_true(is_azure_token(tok))
    expect_identical(resbase, decode_jwt(tok)$payload$aud)
})


test_that("Standalone auth works",
{
    res <- "https://management.azure.com/.default"
    resbase <- "https://management.azure.com"

    auth_uri <- build_authorization_uri(res, tenant, native_app, version=2)
    code <- AzureAuth:::listen_for_authcode(auth_uri, "http://localhost:1410")
    tok <- get_azure_token(res, tenant, native_app, version=2, auth_code=code, use_cache=FALSE)
    expect_identical(tok$hash(), aut_hash)
    expect_identical(resbase, decode_jwt(tok)$payload$aud)

    creds <- get_device_creds(res, tenant, native_app, version=2)
    cat(creds$message, "\n")
    tok2 <- get_azure_token(res, tenant, native_app, auth_type="device_code", version=2, device_creds=creds,
        use_cache=FALSE)
    expect_identical(tok2$hash(), dev_hash)
    expect_identical(resbase, decode_jwt(tok2)$payload$aud)
})


test_that("Webapp authentication works",
{
    res <- "https://management.azure.com/.default"
    resbase <- "https://management.azure.com"

    tok <- get_azure_token(res, tenant, web_app, password=web_app_pwd, auth_type="authorization_code", version=2)
    expect_true(is_azure_token(tok))
    expect_identical(resbase, decode_jwt(tok)$payload$aud)

    tok2 <- get_azure_token(res, tenant, web_app, password=web_app_pwd, version=2)  # client credentials
    expect_true(is_azure_token(tok2))
    expect_identical(tok2$auth_type, "client_credentials")
    expect_identical(resbase, decode_jwt(tok2)$payload$aud)

    tok3 <- get_azure_token(res, tenant, web_app, password=web_app_pwd, username=admin_username,
        auth_type="authorization_code", version=2)
    expect_true(is_azure_token(tok2))
    expect_identical(resbase, decode_jwt(tok3)$payload$aud)

    # web app expects client secret
    expect_error(get_azure_token(res, tenant, web_app, version=2))
})


test_that("Resource owner grant works",
{
    res <- "https://management.azure.com/.default"
    resbase <- "https://management.azure.com"

    tok <- get_azure_token(res, tenant, native_app, password=userpwd, username=username, auth_type="resource_owner",
        version=2)
    expect_true(is_azure_token(tok))
    expect_identical(resbase, decode_jwt(tok)$payload$aud)
})


test_that("Refreshing with changed resource works",
{
    res <- "https://management.azure.com/.default"
    resbase <- "https://management.azure.com"
    res2 <- "offline_access"

    tok <- get_azure_token(c(res, res2), tenant, native_app, version=2)
    expect_identical(resbase, decode_jwt(tok)$payload$aud)

    tok$scope[1] <- "https://graph.microsoft.com/.default"
    tok$refresh()
    expect_identical(decode_jwt(tok)$payload$aud, "https://graph.microsoft.com")
})


test_that("Consumers tenant works",
{
    res <- "https://graph.microsoft.com/.default"
    res2 <- "offline_access"
    res3 <- "openid"

    tok <- get_azure_token(c(res, res2, res3), "consumers", native_app, version=2)
    expect_error(decode_jwt(tok))
    expect_identical(decode_jwt(tok, "id")$payload$tid, "9188040d-6c67-4c5b-b112-36a304b66dad")
})
