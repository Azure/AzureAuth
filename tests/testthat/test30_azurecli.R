test_that("cli auth_type can be selected",
{
    auth_type <- select_auth_type(auth_type = "cli")
    expect_equal(auth_type, "cli")
})

test_that("az account command is assembled properly",
{
    resource <- "my_resource"
    tenant <- "microsoft.com"
    cmd <- build_az_token_cmd(resource = resource, tenant = tenant)
    expect_equal(cmd$command, "az")
    expect_equal(
        cmd$args,
        c(
            "account",
            "get-access-token",
            "--output json",
            "--resource my_resource",
            "--tenant microsoft.com"
        )
    )
})

test_that("az account command is assembled properly even if missing tenant",
{
    resource <- "my_resource"
    cmd <- build_az_token_cmd(resource = resource)
    expect_equal(cmd$command, "az")
    expect_equal(
        cmd$args,
        c(
            "account",
            "get-access-token",
            "--output json",
            "--resource my_resource"
        )
    )
})


test_that("az account command is assembled properly even if missing resource",
{
    tenant <- "microsoft.com"
    cmd <- build_az_token_cmd(tenant = tenant)
    expect_equal(cmd$command, "az")
    expect_equal(
        cmd$args,
        c(
            "account",
            "get-access-token",
            "--output json",
            "--tenant microsoft.com"
        )
    )
})

test_that("the token data from az login response is converted to an R list",
{
    res <- paste(
        '{  "accessToken": "eyJ0",',
        '"expiresOn": "2022-09-23 23:35:16.000000",',
        '"tenant": "microsoft.com",  "tokenType": "Bearer"}'
    )
    expected <- list(
        token_type = "Bearer",
        access_token = "eyJ0",
        expires_on = 1664001316,
        resource = "foo"
    )
    actual <- process_cli_response(res, resource = "foo")
    expect_equal(actual, expected)
})

test_that("the token data from az login is handled by AzureTokenCLI",
{
    res <- paste(
        '{  "accessToken": "eyJ0",',
        '"expiresOn": "2022-09-23 23:35:16.000000",',
        '"tenant": "microsoft.com",  "tokenType": "Bearer"}'
    )
    TestClass <- R6::R6Class(inherit = AzureTokenCLI,
        public = list(
            initialize = function() { self$resource <- "foo" },
            run_test = function() {
                private$process_response(res)
            }
        )
    )
    expected <- list(
        token_type = "Bearer",
        access_token = "eyJ0",
        expires_on = 1664001316,
        resource = "foo"
    )
    tc <- TestClass$new()
    expect_equal(tc$run_test(), expected)
})

test_that("the appropriate error is thrown when the az CLI is not installed",
{
    expect_error(
        execute_az_token_cmd(
                build_az_token_cmd(
                "bnrwfq", # pass a different command name that is unlikely to exist
                resource = "foo",
                tenant = "bar"
            )
        ),
        regexp = "bnrwfq is not installed."
    )
})

test_that("invalid scope error is handled", {
    msg <- paste0(
        "ERROR: AADSTS70011: The provided request must include a 'scope' input parameter. ",
        "The provided value for the input parameter 'scope' is not valid. ",
        "The scope my_resource/.default offline_access openid profile is not valid. ",
        "The scope format is invalid. ",
        "Scope must be in a valid URI form <https://example/scope> or a valid Guid <guid/scope>.\n",
        "Trace ID: 09da0917-570a-4f10-93f0-a61340d06300\n",
        "Correlation ID: 6d2114db-6f1a-43fa-8484-b0a6783cf47b\n",
        "Timestamp: 2022-10-10 22:55:14Z\n",
        "To re-authenticate, please run:\n",
        "az login --scope my_resource/.default"
    )
    expect_error(, regexp = "")
})

if (Sys.which("az") == "")
    skip("az not installed, skipping tests.")

# cond <- system2("az", args = c("account show"), stdout = TRUE)
# not_loggedin <- grepl("az login", cond, fixed = TRUE) |
#                         grepl("az account set", cond, fixed = TRUE)
# if (not_loggedin)
#     skip("az not logged in, skipping tests.")

test_that("the appropriate error is thrown when the resource is invalid",
{

    fail("TODO")
})

test_that("the appropriate error is thrown when az login fails",
{
    fail("TODO")
})


test_that("az login is called if the user is not already logged in",
{
    fail("TODO")
})

test_that("token is successfully retrieved if user is logged in",
{
    fail("TODO")
})