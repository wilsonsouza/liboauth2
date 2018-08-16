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
*  08/16/2018 removed dependency of libaulstring.lib
*  Version 0.1-beta
* 
*  Dependencies: restbed, libjson
*/
#include <std_oauth_v2.hpp>
#include <std_json.hpp>
#include <restbed>
#pragma warning(disable:4101)
//-----------------------------------------------------------------------------------------------//
using http_request = restbed::Request;
using builder_uri = restbed::Uri;
using http = restbed::Http;
//-----------------------------------------------------------------------------------------------//
std::oauth_v2::builder::builder(std::string const & client, std::string const & secret_key)
{
   m_config->client_id = client;
   m_config->client_secret = secret_key;
   m_config->last_error->id = error::SUCCESS;
}
//-----------------------------------------------------------------------------------------------//
/*
*Set the redirect URI for auth code authentication.
*This must be set before using oauth2_request_auth_code too.
*/
void std::oauth_v2::builder::set_redirect_uri(std::string const & redirect_uri)
{
   m_config->redirect_uri = redirect_uri;
}
//-----------------------------------------------------------------------------------------------//
void std::oauth_v2::builder::set_auth_code(std::string const & auth_code)
{
   m_config->auth_code = auth_code;
}
//-----------------------------------------------------------------------------------------------//
/* returns URL to redirect user to*/
std::string std::oauth_v2::builder::request_auth_code(std::string const & auth_server,
                                                      std::string const & scope,
                                                      std::string const & state)
{
   auto data = string{ auth_server };
   /**/
   data.append("?response_type=code");
   data.append("&client_id=").append(m_config->client_id);
   data.append("&redirect_uri=").append(m_config->redirect_uri);
   /**/
   if (!scope.empty())
   {
      data.append("&scope=").append(scope);
   }
   /**/
   if (!state.empty())
   {
      data.append("&state=").append(state);
   }
   /**/
   return data;
}
//-----------------------------------------------------------------------------------------------//
std::string std::oauth_v2::builder::access_auth_code(std::string const & auth_server,
                                                     std::string const & auth_code,
                                                     std::string const & scope)
{
   auto data = string{ auth_server };
   /**/
   data.append("grant_type=authorization_code");
   data.append("&client_id=").append(m_config->client_id);
   data.append("&client_secret=").append(m_config->client_secret);
   data.append("&code=").append(auth_code);
   data.append("&redirect_uri=").append(m_config->redirect_uri);
   /* make call */
   auto req = make_shared<http_request>(builder_uri(data));
   auto res = http::sync(req);
   auto body = res->get_body();
   /**/
   data.assign(string(body.begin(), body.end()));
   return data;
}
//-----------------------------------------------------------------------------------------------//
std::string std::oauth_v2::builder::access_resource_owner(std::string const & auth_server,
                                                          std::string const & user_name,
                                                          std::string const & password)
{
   auto data = string{ auth_server };
   /**/
   data.append("grant_type=password");
   data.append("&client_id").append(m_config->client_id);
   data.append("&username=").append(user_name);
   data.append("&password=").append(password);
   /* make call uri */
   auto req = make_shared<http_request>(builder_uri(data));
   auto res = http::sync(req);
   auto body = res->get_body();
   /**/
   data.assign(string(body.begin(), body.end()));
   return data;
}
//-----------------------------------------------------------------------------------------------//
std::string std::oauth_v2::builder::access_refresh_token(std::string const & refresh_token)
{
   return string{};
}
//-----------------------------------------------------------------------------------------------//
std::string std::oauth_v2::builder::request(std::string const & uri, std::string const & params)
{
   auto data = string{ uri };
   /**/
   if (data.empty())
   {
      return data;
   }
   /**/
   data.append(params);
   data.append("&access_token=").append(m_config->auth_code);
   /* make call */
   auto req = make_shared<http_request>(builder_uri(data));
   auto res = http::sync(req);
   auto body = res->get_body();
   /**/
   data.assign(string(body.begin(), body.end()));
   return data;
}
//-----------------------------------------------------------------------------------------------//
/* set google token file data*/
bool std::oauth_v2::builder::set_google_file_token(std::string const & json_token_buffer) noexcept
{
   try
   {
      auto body = json::value::parse(json_token_buffer);
      /**/
      if (body.empty())
      {
         throw std::exception("client file key is empty!!!");
      }
      /**/
      m_google->auth_provider_x509_cert_url = body["auth_provider_x509_cert_url"].get<string>();
      m_google->auth_uri = body["auth_uri"].get<string>();
      m_google->client_email = body["client_email"].get<string>();
      m_google->client_id = body["client_id"].get<string>();
      m_google->client_x509_cert_url = body["client_x509_cert_url"].get<string>();
      m_google->private_key = body["private_key"].get<string>();
      m_google->private_key_id = body["private_key_id"].get<string>();
      m_google->project_id = body["project_id"].get<string>();
      m_google->token_uri = body["token_uri"].get<string>();
      m_google->type = body["type"].get<string>();
      /**/
      return true;
   }
   catch (std::exception const & e)
   {
   }
   return false;
}
//-----------------------------------------------------------------------------------------------//
std::oauth_v2::google_file_token_data::pointer const & std::oauth_v2::builder::get_google_file_token_from_data() noexcept
{
   return m_google;
}
//-----------------------------------------------------------------------------------------------//
