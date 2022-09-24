test_that("cli auth_type can be selected",
{
    auth_type <- select_auth_type(auth_type = "cli")
    expect_equal(auth_type, "cli")
})

test_that("the output of az login is handled appropriately",
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
    expected <- list(token_type = "Bearer",
                     access_token = "eyJ0",
                     expires_on = 1664001316,
                     resource = "foo")
    tc <- TestClass$new()
    expect_equal(expected, tc$run_test())
})

test_that("the appropriate error is thrown when az is not installed",
{
    expect_error(build_access_token_cmd("bnrwfq", resource = "foo", tenant = "bar"),
                 regexp = "bnrwfq is not installed.")
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