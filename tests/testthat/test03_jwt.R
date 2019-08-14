context("JWT")

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


test_that("JWT functions work",
{
    res <- "https://management.azure.com/"
    tok <- get_azure_token(res, tenant, native_app)

    decoded <- decode_jwt(tok)
    expect_type(decoded, "list")
    expect_identical(names(decoded), c("header", "payload", "signature"))

    extracted <- extract_jwt(tok)
    expect_type(extracted, "character")

    expect_identical(decoded, decode_jwt(extracted))

    decoded_id <- decode_jwt(tok, "id")
    expect_type(decoded_id, "list")
    expect_identical(names(decoded_id), c("header", "payload"))

    extracted_id <- extract_jwt(tok, "id")
    expect_type(extracted_id, "character")

    expect_identical(decoded_id, decode_jwt(extracted_id))
})


test_that("JWT functions work with AAD v2.0",
{
    res <- "https://management.azure.com/.default"
    tok <- get_azure_token(c(res, "openid"), tenant, native_app, version=2)

    decoded <- decode_jwt(tok)
    expect_type(decoded, "list")
    expect_identical(names(decoded), c("header", "payload", "signature"))

    extracted <- extract_jwt(tok)
    expect_type(extracted, "character")

    expect_identical(decoded, decode_jwt(extracted))

    decoded_id <- decode_jwt(tok, "id")
    expect_type(decoded_id, "list")
    expect_identical(names(decoded_id), c("header", "payload", "signature"))

    extracted_id <- extract_jwt(tok, "id")
    expect_type(extracted_id, "character")

    expect_identical(decoded_id, decode_jwt(extracted_id))
})
