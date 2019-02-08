context("Normalize")

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

