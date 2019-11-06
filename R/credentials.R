TokenCredentials <- R6::R6Class("TokenCredentials",

public=list(

    initialize=function(credentials, hash)
    {
        private$set_credentials(credentials)
        private$hash <- hash
        private$set_expiry_time()
    }
),

active=list(

    expires_on=function() private$credentials$expires_on,

    expires_in=function() private$credentials$expires_in,

    ext_expires_in=function() private$credentials$ext_expires_in,

    not_before=function() private$credentials$not_before,

    token_type=function() private$credentials$token_type,

    resource=function() private$credentials$resource,

    scope=function() private$credentials$scope,

    access_token=function() private$credentials$access_token,

    id_token=function() private$credentials$id_token,

    refresh_token=function() private$credentials$refresh_token
),

private=list(

    credentials=NULL,
    hash=NULL,

    set_expiry_time=function()
    {
        # v2.0 endpoint doesn't provide an expires_on field, set it here
        if(is.null(private$credentials$expires_on))
        {
            expiry <- try(as.character(decode_jwt(private$credentials$access_token)$payload$exp), silent=TRUE)
            if(inherits(expiry, "try-error"))
            {
                expiry <- try(as.character(decode_jwt(private$credentials$id_token)$payload$exp), silent=TRUE)
                if(inherits(expiry, "try-error"))
                {
                    warning("Expiry date not found", call.=FALSE)
                    expiry <- NA
                }
            }
            private$credentials$expires_on <- expiry
        }
    },

    set_credentials=function(creds)
    {
        private$credentials <- creds
    }
))
