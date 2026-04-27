require "oauth2"

module Koauth::Oauth
  abstract class provider
    getter name : String
    getter user_url : String
    getter client_id : String
    getter client_secret : String
    getter scope : String
    getter auth_url : String
    getter token_url : String

    def initialize(@name, @client_id, @client_secret, @scope = "")
    end 

    abstract def user_info(access_token : OAuth2::AccessToken) : NamedTuple

    protected def client(redirect_uri : String) : OAuth2::Client
      OAuth::Client.new(
        auth_url, token_url, client_id, client_secret, redirect_url: redirect_uri)
    end 

    def authorize_uri(redirect_uri : String, state : String) : String
      client(redirect_uri).get_authorize_uri(scope: scope, state: state)
    end 

    def exchange_code(code : String, redirect_uri : String)
      OAuth2::AccessToken
      client(redirect_uri).get_access_token_using_authorization_code(code)
    end 
  end 
end 
