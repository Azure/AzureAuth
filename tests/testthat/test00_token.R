context("AzureToken")

test_that("normalize_tenant, normalize_guid work",
{
    guid <- "abcdefab-1234-5678-9012-abcdefabcdef"
    expect_identical(normalize_guid(guid), guid)
    guid2 <- paste0("{", guid, "}")
    expect_identical(normalize_guid(guid2), guid)
    guid3 <- paste0("(", guid, ")")
    expect_identical(normalize_guid(guid3), guid)
    guid4 <- gsub("-", "", guid, fixed=TRUE)
    expect_identical(normalize_guid(guid4), guid)

    # improperly formatted GUID will be treated as a name
    guid5 <- paste0("(", guid)
    expect_false(is_guid(guid5))
    expect_error(normalize_guid(guid5))
    expect_identical(normalize_tenant(guid5), paste0(guid5, ".onmicrosoft.com"))

    expect_identical(normalize_tenant("common"), "common")
    expect_identical(normalize_tenant("mytenant"), "mytenant.onmicrosoft.com")
    expect_identical(normalize_tenant("mytenant.com"), "mytenant.com")
    # iterating normalize shouldn't change result
    expect_identical(normalize_tenant(normalize_tenant("mytenant")), "mytenant.onmicrosoft.com")
})


tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
password <- Sys.getenv("AZ_TEST_PASSWORD")
subscription <- Sys.getenv("AZ_TEST_SUBSCRIPTION")
native_app <- Sys.getenv("AZ_TEST_NATIVE_APP_ID")

if(tenant == "" || app == "" || password == "" || subscription == "" || native_app == "")
    skip("Authentication tests skipped: ARM credentials not set")

if(system.file(package="httpuv") == "")
    skip("Authentication tests skipped: httpuv must be installed")

# not a perfect test: will fail to detect Linux DSVM issue
if(!interactive())
    skip("Authentication tests skipped: must be an interactive session")

test_that("Authentication works",
{
    suppressWarnings(file.remove(dir(AzureR_dir(), full.names=TRUE)))

    res <- "https://management.azure.com/"

    # obtain new tokens
    aut_tok <- get_azure_token(res, tenant, native_app, auth_type="authorization_code")
    expect_true(is_azure_token(aut_tok))
    expect_identical(aut_tok$hash(), "b29ef592fa435a4fd92672daf8726bae")

    ccd_tok <- get_azure_token(res, tenant, app, password=password)
    expect_true(is_azure_token(ccd_tok))
    expect_identical(ccd_tok$hash(), "c75c266d9c578af29e24d3f22013ebf6")

    dev_tok <- get_azure_token(res, tenant, native_app, auth_type="device_code")
    expect_true(is_azure_token(dev_tok))
    expect_identical(dev_tok$hash(), "37cbd9fec7c15b5a47edc1ea6f2f2747")

    aut_expire <- as.numeric(aut_tok$credentials$expires_on)
    ccd_expire <- as.numeric(ccd_tok$credentials$expires_on)
    dev_expire <- as.numeric(dev_tok$credentials$expires_on)

    Sys.sleep(5)

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
    expect_identical(aut_tok2$hash(), "b29ef592fa435a4fd92672daf8726bae")

    ccd_tok2 <- get_azure_token(res, tenant, app, password=password)
    expect_true(is_azure_token(ccd_tok2))
    expect_identical(ccd_tok2$hash(), "c75c266d9c578af29e24d3f22013ebf6")

    dev_tok2 <- get_azure_token(res, tenant, native_app, auth_type="device_code")
    expect_true(is_azure_token(dev_tok2))
    expect_identical(dev_tok2$hash(), "37cbd9fec7c15b5a47edc1ea6f2f2747")

    expect_null(delete_azure_token(res, tenant, native_app, auth_type="authorization_code", confirm=FALSE))
    expect_null(delete_azure_token(res, tenant, app, password=password, confirm=FALSE))
    expect_null(delete_azure_token(res, tenant, native_app, auth_type="device_code", confirm=FALSE))
})
