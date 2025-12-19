context("Manual Token")

# Helper function to create a sample JWT for testing
# This creates a valid JWT structure (header.payload.signature) without actual signing
create_test_jwt <- function(claims = list(), exp_offset = 3600)
{
    header <- list(typ = "JWT", alg = "RS256")

    # Default claims
    default_claims <- list(
        aud = "https://graph.microsoft.com",
        iss = "https://sts.windows.net/test-tenant-id/",
        iat = as.integer(Sys.time()),
        exp = as.integer(Sys.time()) + exp_offset,
        tid = "test-tenant-id",
        ver = "2.0",
        scp = "User.Read Mail.Read"
    )

    # Merge with provided claims
    payload <- utils::modifyList(default_claims, claims)

    # Base64url encode header and payload
    header_b64 <- jose::base64url_encode(charToRaw(jsonlite::toJSON(header, auto_unbox = TRUE)))
    payload_b64 <- jose::base64url_encode(charToRaw(jsonlite::toJSON(payload, auto_unbox = TRUE)))

    # Create a fake signature (not cryptographically valid, but structurally correct)
    sig_b64 <- jose::base64url_encode(charToRaw("fake-signature-for-testing"))

    paste(header_b64, payload_b64, sig_b64, sep = ".")
}


test_that("get_manual_token creates AzureManualToken object",
{
    test_token <- create_test_jwt()

    tok <- get_manual_token(test_token)

    expect_true(inherits(tok, "AzureManualToken"))
    expect_true(inherits(tok, "AzureToken"))
    expect_true(R6::is.R6(tok))
})


test_that("AzureManualToken passes is_azure_token check",
{
    test_token <- create_test_jwt()

    tok <- get_manual_token(test_token)

    expect_true(is_azure_token(tok))
})


test_that("AzureManualToken parses JWT claims correctly",
{
    test_token <- create_test_jwt(list(
        tid = "my-custom-tenant",
        aud = "https://management.azure.com/",
        ver = "2.0"
    ))

    tok <- get_manual_token(test_token)

    expect_equal(tok$tenant, "my-custom-tenant")
    expect_equal(tok$resource, "https://management.azure.com/")
    expect_equal(tok$version, 2)
    expect_equal(tok$auth_type, "manual")
})


test_that("AzureManualToken extracts scopes from scp claim",
{
    test_token <- create_test_jwt(list(
        scp = "User.Read User.ReadWrite Directory.Read"
    ))

    tok <- get_manual_token(test_token)

    expect_true(is.character(tok$scope))
    expect_true("User.Read" %in% tok$scope)
    expect_true("User.ReadWrite" %in% tok$scope)
    expect_true("Directory.Read" %in% tok$scope)
})


test_that("AzureManualToken user-provided values override JWT claims",
{
    test_token <- create_test_jwt(list(
        tid = "jwt-tenant",
        aud = "jwt-resource"
    ))

    tok <- get_manual_token(test_token, tenant = "override-tenant", resource = "override-resource")

    expect_equal(tok$tenant, "override-tenant")
    expect_equal(tok$resource, "override-resource")
})


test_that("AzureManualToken validates expiration correctly",
{
    # Token expiring in 1 hour - should be valid
    valid_token <- create_test_jwt(exp_offset = 3600)
    tok_valid <- get_manual_token(valid_token)
    expect_true(tok_valid$validate())

    # Token expired 1 hour ago - should be invalid
    expired_token <- create_test_jwt(exp_offset = -3600)
    tok_expired <- get_manual_token(expired_token)
    expect_false(tok_expired$validate())
})


test_that("AzureManualToken can_refresh returns FALSE",
{
    test_token <- create_test_jwt()
    tok <- get_manual_token(test_token)

    expect_false(tok$can_refresh())
})

test_that("AzureManualToken stores raw token in credentials",
{
    test_token <- create_test_jwt()
    tok <- get_manual_token(test_token)

    expect_equal(tok$credentials$access_token, test_token)
    expect_equal(tok$credentials$token_type, "Bearer")
})


test_that("AzureManualToken accepts custom token type",
{
    test_token <- create_test_jwt()
    tok <- get_manual_token(test_token, type = "CustomType")

    expect_equal(tok$credentials$token_type, "CustomType")
})


test_that("AzureManualToken hash is consistent",
{
    test_token <- create_test_jwt()
    tok1 <- get_manual_token(test_token)
    tok2 <- get_manual_token(test_token)

    expect_equal(tok1$hash(), tok2$hash())
})


test_that("AzureManualToken hash differs for different tokens",
{
    tok1 <- get_manual_token(create_test_jwt(list(tid = "tenant1")))
    tok2 <- get_manual_token(create_test_jwt(list(tid = "tenant2")))

    expect_false(tok1$hash() == tok2$hash())
})


test_that("AzureManualToken cache returns NULL invisibly",
{
    test_token <- create_test_jwt()
    tok <- get_manual_token(test_token)

    result <- tok$cache()
    expect_null(result)
})


test_that("AzureManualToken print works",
{
    test_token <- create_test_jwt()
    tok <- get_manual_token(test_token)

    expect_output(print(tok), "manual")
    expect_output(print(tok), "cannot be refreshed")
})


test_that("get_manual_token rejects empty token",
{
    expect_error(get_manual_token(""), "non-empty token")
    expect_error(get_manual_token(NULL), "non-empty token")
    expect_error(get_manual_token(), "non-empty token")
})


test_that("AzureManualToken handles opaque (non-JWT) tokens gracefully",
{
    opaque_token <- "this-is-not-a-jwt-just-a-random-string"

    # Should not error, just warn about parsing
    expect_message(tok <- get_manual_token(opaque_token), "could not be parsed")

    # Should still create valid object with defaults
    expect_true(is_azure_token(tok))
    expect_equal(tok$credentials$access_token, opaque_token)
    expect_equal(tok$tenant, "unknown")
    expect_equal(tok$resource, "unknown")
})


test_that("AzureManualToken handles malformed JWT gracefully",
{
    # JWT with invalid base64
    malformed_token <- "not.valid.base64!"

    expect_message(tok <- get_manual_token(malformed_token), "could not be parsed")
    expect_true(is_azure_token(tok))
})


test_that("decode_jwt works on AzureManualToken",
{
    test_token <- create_test_jwt(list(tid = "test-tenant"))
    tok <- get_manual_token(test_token)

    decoded <- decode_jwt(tok)

    expect_type(decoded, "list")
    expect_true("header" %in% names(decoded))
    expect_true("payload" %in% names(decoded))
    expect_equal(decoded$payload$tid, "test-tenant")
})


test_that("extract_jwt works on AzureManualToken",
{
    test_token <- create_test_jwt()
    tok <- get_manual_token(test_token)

    extracted <- extract_jwt(tok)

    expect_type(extracted, "character")
    expect_equal(extracted, test_token)
})


test_that("AzureManualToken detects v1.0 tokens from ver claim",
{
    v1_token <- create_test_jwt(list(ver = "1.0"))
    tok <- get_manual_token(v1_token)

    expect_equal(tok$version, 1)
    expect_true(is_azure_v1_token(tok))
    expect_false(is_azure_v2_token(tok))
})


test_that("AzureManualToken detects v2.0 tokens from ver claim",
{
    v2_token <- create_test_jwt(list(ver = "2.0"))
    tok <- get_manual_token(v2_token)

    expect_equal(tok$version, 2)
    expect_false(is_azure_v1_token(tok))
    expect_true(is_azure_v2_token(tok))
})


test_that("AzureManualToken sets expires_in correctly",
{
    current_time <- as.integer(Sys.time())
    test_token <- create_test_jwt(list(
        iat = current_time,
        exp = current_time + 7200  # 2 hours
    ))

    tok <- get_manual_token(test_token)

    # expires_in should be approximately 7200 (may differ slightly due to timing)
    expires_in <- as.numeric(tok$credentials$expires_in)
    expect_true(expires_in > 7000 && expires_in <= 7200)
})
