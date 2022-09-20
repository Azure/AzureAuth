test_that("azure_cli auth_type can be selected", {
    auth_type <- select_auth_type(auth_type = "azure_cli")
    expect_equal(auth_type, "azure_cli")
})