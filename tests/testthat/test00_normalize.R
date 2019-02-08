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


test_that("verify_v2_scope works",
{
    expect_silent(AzureAuth:::verify_v2_scope("https://resource.com/.default"))

    # supported OpenID scope
    expect_silent(AzureAuth:::verify_v2_scope("offline_access"))

    # unsupported OpenID scope
    expect_error(AzureAuth:::verify_v2_scope("address"))

    # no scope path
    expect_warning(newscope <- AzureAuth:::verify_v2_scope("https://resource"))
    expect_equal(newscope, "https://resource/.default")
    expect_warning(newscope <- AzureAuth:::verify_v2_scope("https://resource/"))
    expect_equal(newscope, "https://resource/.default")

    # GUIDs
    expect_silent(AzureAuth:::verify_v2_scope("12345678901234567890123456789012/.default"))
    expect_warning(newscope <- AzureAuth:::verify_v2_scope("12345678901234567890123456789012"))
    expect_equal(newscope, "12345678901234567890123456789012/.default")
    expect_warning(newscope <- AzureAuth:::verify_v2_scope("12345678901234567890123456789012/"))
    expect_equal(newscope, "12345678901234567890123456789012/.default")

    # not a URI or GUID
    expect_error(AzureAuth:::verify_v2_scope("resource"))
    expect_error(AzureAuth:::verify_v2_scope("resource/.default"))
})
