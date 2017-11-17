/*
*  std oauth version 2.0 authenticate library for c++14
*
*  Created by wilson.souza
*  Default language used c++14
*
*  Copyright (c) 2017 WR DevInfo
*
*  Created oct 10 2017
*  Last updated
*  Version 0.1-beta
*/
#pragma once
#include <memory>
#include <algorithm>
#include <string>
//-----------------------------------------------------------------------------------------------//
namespace std
{
   namespace oauth_v2
   {
      enum response : uint16_t
      {
         CODE = 0, /*oauth2_response_code*/
         TOKEN, /*oauth2_reponse_token*/
         TOKEN_AND_CODE /*oauth2_reponse_token_and_code*/
      };
      /**/
      enum error : uint16_t
      {
         SUCCESS = 0,
         INVALID_REQUEST,
         INVALID_CLIENT,
         UNAUTHORIZED_CLIENT,
         REDIRECT_URI_MISTMATCH,
         ACCESS_DENIED,
         UNSUPPORTED_RESPONSE_TYPE,
         INVALID_SCOPE,
         INVALID_GRANT,
         UNSUPPORTED_GRANT_TYPE
      };
      /**/
      struct data_error
      {
         using pointer = shared_ptr<data_error>;
         data_error( ) = default;

         error id;
         string description;
         string uri;
         string state;
      };
      /**/
      struct google_file_token_data
      {
         using pointer = shared_ptr<google_file_token_data>;
         google_file_token_data( ) = default;

         string type;
         string project_id;
         string private_key_id;
         string private_key;
         string client_email;
         string client_id;
         string auth_uri;
         string token_uri;
         string auth_provider_x509_cert_url;
         string client_x509_cert_url;
      };
      /**/
      struct config
      {
         using pointer = shared_ptr<config>;
         config( ) = default;

         string client_id;
         string client_secret;
         string redirect_uri;
         string auth_code;
         data_error::pointer last_error = data_error::pointer( new data_error( ) );
      };
      /**/
      class builder
      {
      public:
         using pointer = shared_ptr<builder>;
      protected:
         config::pointer m_config = config::pointer( new config( ) );
         google_file_token_data::pointer m_google = google_file_token_data::pointer( new google_file_token_data( ) );

      public:
         builder( ) = default;
         builder( builder const & owner ) = delete;
         builder( string const & client, string const & secret_key );
         /*
         *Set the redirect URI for auth code authentication.
         *This must be set before using oauth2_request_auth_code too.
         */
         void set_redirect_uri( string const & redirect_uri );
         void set_auth_code( string const & auth_code );
         /* returns URL to redirect user to*/
         string const & request_auth_code( string const & auth_server,
                                           string const & scope,
                                           string const & state );
         string const & access_auth_code( string const & auth_server,
                                          string const & auth_code,
                                          string const & scope );
         string const & access_resource_owner( string const & auth_server,
                                               string const & user_name,
                                               string const & password );
         string const & access_refresh_token( string const & refresh_token );
         string const & request( string const & uri, string const & params );

         /* set google token file data*/
         bool set_google_file_token( string const & json_token_buffer ) noexcept;
         google_file_token_data::pointer const & get_google_file_token_from_data( ) noexcept;
      };
   }
}
//-----------------------------------------------------------------------------------------------//
