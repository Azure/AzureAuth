test_that("cli auth_type can be selected",
{
    auth_type <- select_auth_type(auth_type = "cli")
    expect_equal(auth_type, "cli")
})

test_that("the appropriate error is thrown when az is not installed",
{
    # TODO
    fail("TODO")
})