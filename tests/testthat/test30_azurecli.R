test_that("cli auth_type can be selected",
{
    auth_type <- select_auth_type(auth_type = "cli")
    expect_equal(auth_type, "cli")
})

test_that("token is successfully retrieved if user is logged in",
{
    fail("TODO")
})

test_that("az login is called if the user is not already logged in",
{
    fail("TODO")
})

test_that("the output of az login is handled appropriately",
{
    fail("TODO")
})

test_that("the appropriate error is thrown when az is not installed",
{
    fail("TODO")
})

test_that("the appropriate error is thrown when the resource is invalid",
{
    fail("TODO")
})

test_that("the appropriate error is thrown when az login fails",
{
    fail("TODO")
})