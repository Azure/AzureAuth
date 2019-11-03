TokenCredentials <- R6::R6Class("TokenCredentials",

public=list(

    initialize=function(credentials, hash)
    {
        private$set_credentials(credentials)
        private$hash <- hash
    }
),

active=list(

    expires_on=function(value)
    {
        if(missing(value))
            return(private$credentials$expires_on)
        else private$credentials$expires_on <- value
    },

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

    set_credentials=function(creds)
    {
        private$credentials <- creds
    }
))
