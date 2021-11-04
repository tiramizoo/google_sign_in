require 'oauth2'

class GoogleSignIn::BaseController < ActionController::Base
  protect_from_forgery with: :exception

  private
    def client
      @client ||= OAuth2::Client.new \
        GoogleSignIn.client_id,
        GoogleSignIn.client_secret,
        authorize_url: 'https://accounts.google.com/o/oauth2/auth',
        token_url: 'https://oauth2.googleapis.com/token',
        redirect_uri: ENV['GOOGLE_SIGN_IN_MAIN_DOMAIN'] + callback_path(callback_subdomain: callback_subdomain)
    end

    def callback_subdomain
      uri = URI(callback_url)

      if uri.host.split('.').size > 2
        callback_subdomain = uri.host.split('.').first
      end

      callback_subdomain
    end
end
