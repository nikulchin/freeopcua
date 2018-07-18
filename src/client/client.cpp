/******************************************************************************
 *   Copyright (C) 2014-2014 by Sintef Raufoss Manufacturing                  *
 *   olivier.roulet@gmail.com                  *
 *                                          *
 *   This library is free software; you can redistribute it and/or modify     *
 *   it under the terms of the GNU Lesser General Public License as          *
 *   published by the Free Software Foundation; version 3 of the License.     *
 *                                          *
 *   This library is distributed in the hope that it will be useful,          *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *   GNU Lesser General Public License for more details.              *
 *                                          *
 *   You should have received a copy of the GNU Lesser General Public License *
 *   along with this library; if not, write to the                  *
 *   Free Software Foundation, Inc.,                          *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.              *
 ******************************************************************************/

#include <opc/ua/client/client.h>

#include <opc/common/uri_facade.h>
#include <opc/ua/client/remote_connection.h>
#include <opc/ua/services/services.h>
#include <opc/ua/node.h>
#include <opc/ua/protocol/string_utils.h>

#ifdef SSL_SUPPORT_MBEDTLS
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>
#endif

namespace OpcUa
{

void KeepAliveThread::Start(Services::SharedPtr server, Node node, Duration period)
{
  Server = server;
  NodeToRead = node;
  Period = period;
  Running = true;
  StopRequest = false;
  Thread = std::thread([this] { this->Run(); });
}


void KeepAliveThread::Run()
{
  LOG_INFO(Logger, "keep_alive_thread     | starting");

  while (!StopRequest)
    {
      int64_t t_sleep = Period * 0.7;
      LOG_DEBUG(Logger, "keep_alive_thread     | sleeping for: {}ms", t_sleep);

      std::unique_lock<std::mutex> lock(Mutex);
      std::cv_status status = Condition.wait_for(lock, std::chrono::milliseconds(t_sleep));

      if (status == std::cv_status::no_timeout)
        {
          break;
        }

      LOG_DEBUG(Logger, "keep_alive_thread     | renewing secure channel");

      OpenSecureChannelParameters params;
      params.ClientProtocolVersion = 0;
      params.RequestType = SecurityTokenRequestType::Renew;
      params.SecurityMode = MessageSecurityMode::None;
      params.ClientNonce = std::vector<uint8_t>(1, 0);
      params.RequestLifeTime = Period;
      OpenSecureChannelResponse response = Server->OpenSecureChannel(params);

      if ((response.ChannelSecurityToken.RevisedLifetime < Period) && (response.ChannelSecurityToken.RevisedLifetime > 0))
        {
          Period = response.ChannelSecurityToken.RevisedLifetime;
        }

      LOG_DEBUG(Logger, "keep_alive_thread     | read a variable from address space to keep session open");

      NodeToRead.GetValue();
    }

  Running = false;

  LOG_INFO(Logger, "keep_alive_thread     | stopped");
}

void KeepAliveThread::Stop()
{
  if (!Running) { return; }

  LOG_DEBUG(Logger, "keep_alive_thread     | stopping");

  StopRequest = true;
  Condition.notify_all();

  try
    {
      Thread.join();
    }

  catch (std::system_error ex)
    {
      LOG_ERROR(Logger, "keep_alive_thread     | exception thrown at attempt to join: {}", ex.what());

      throw ex;
    }
}

UaClient::UaClient(bool debug)
  : KeepAlive(nullptr)
{
  Logger = spdlog::get("UaClient");
  if (!Logger)
    {
      Logger = spdlog::stderr_color_mt("UaClient");
    }
  if (debug)
    {
      Logger->set_level(spdlog::level::debug);
    }
  else
    {
      Logger->set_level(spdlog::level::info);
    }
  KeepAlive.SetLogger(Logger);
}

std::vector<EndpointDescription> UaClient::GetServerEndpoints(const std::string & endpoint)
{
  const Common::Uri serverUri(endpoint);
  OpcUa::IOChannel::SharedPtr channel = OpcUa::Connect(serverUri.Host(), serverUri.Port(), Logger);

  OpcUa::SecureConnectionParams params;
  params.EndpointUrl = endpoint;
  params.SecurePolicy = "http://opcfoundation.org/UA/SecurityPolicy#None";

  Server = OpcUa::CreateBinaryClient(channel, params, Logger);

  OpenSecureChannel();
  std::vector<EndpointDescription> endpoints = UaClient::GetServerEndpoints();
  CloseSecureChannel();

  Server.reset(); //close channel

  return endpoints;
}

std::vector<EndpointDescription> UaClient::GetServerEndpoints()
{
  GetEndpointsParameters filter;
  filter.EndpointUrl = Endpoint.EndpointUrl;
  filter.ProfileUris.push_back("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary");
  filter.LocaleIds.push_back("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary");
  std::vector<EndpointDescription> endpoints =  Server->Endpoints()->GetEndpoints(filter);

  return endpoints;
}

EndpointDescription UaClient::SelectEndpoint(const std::string & endpoint)
{
  std::vector<EndpointDescription> endpoints = GetServerEndpoints(endpoint);

  LOG_DEBUG(Logger, "ua_client             | going through server endpoints and selected one we support");

  Common::Uri uri(endpoint);
  bool has_login = !uri.User().empty();

  for (EndpointDescription ed : endpoints)
    {
      LOG_DEBUG(Logger, "ua_client             | examining endpoint: {} with security: {}", ed.EndpointUrl, ed.SecurityPolicyUri);

      if (ed.SecurityPolicyUri == "http://opcfoundation.org/UA/SecurityPolicy#None")
        {
          LOG_DEBUG(Logger, "ua_client             | security policy is OK, now looking at user token");

          if (ed.UserIdentityTokens.empty())
            {
              LOG_DEBUG(Logger, "ua_client             | server does not use user token, OK");

              return ed;
            }

          for (UserTokenPolicy token : ed.UserIdentityTokens)
            {
              if (has_login)
                {
                  if (token.TokenType == UserTokenType::UserName)
                    {
                      LOG_DEBUG(Logger, "ua_client             | endpoint selected");

                      return ed;
                    }
                }

              else if (token.TokenType == UserTokenType::Anonymous)
                {
                  LOG_DEBUG(Logger, "ua_client             | endpoint selected");

                  return ed;
                }
            }
        }
    }

  throw std::runtime_error("No supported endpoints found on server");
}

void UaClient::Connect(const std::string & endpoint)
{
  EndpointDescription endpointdesc = SelectEndpoint(endpoint);
  endpointdesc.EndpointUrl = endpoint; //force the use of the enpoint the user wants, seems like servers often send wrong hostname
  Connect(endpointdesc);
}
void UaClient::Connect(const EndpointDescription & endpoint,std::string user, std::string host, unsigned port) {
	  Endpoint = endpoint;
	  OpcUa::IOChannel::SharedPtr channel = OpcUa::Connect(host, port, Logger);

	  OpcUa::SecureConnectionParams params;
	   params.EndpointUrl = Endpoint.EndpointUrl;
	   params.SecurePolicy = "http://opcfoundation.org/UA/SecurityPolicy#None";

	   Server = OpcUa::CreateBinaryClient(channel, params, Logger);

	   OpenSecureChannel();


	   LOG_INFO(Logger, "ua_client             | creating session ...");

	   OpcUa::RemoteSessionParameters session;
	   session.ClientDescription.ApplicationUri = ApplicationUri;
	   session.ClientDescription.ProductUri = ProductUri;
	   session.ClientDescription.ApplicationName = LocalizedText(SessionName);
	   session.ClientDescription.ApplicationType = OpcUa::ApplicationType::Client;
	   session.SessionName = SessionName;
	   session.EndpointUrl = endpoint.EndpointUrl;
	   session.Timeout = DefaultTimeout;
	   session.ServerURI = endpoint.Server.ApplicationUri;

	   CreateSessionResponse createSessionResponse = Server->CreateSession(session);
	   CheckStatusCode(createSessionResponse.Header.ServiceResult);

	   LOG_INFO(Logger, "ua_client             | create session OK");

	   LOG_INFO(Logger, "ua_client             | activating session ...");

	   ActivateSessionParameters sessionParameters;
	   {
	     //const SessionData &session_data = response.Session;
	     //Common::Uri uri(session.EndpointUrl);
	     //std::string user = uri.User();
	     //std::string password = uri.Password();
	     //password = std::string("\x5f\x1f\x03\xf6\x88\x5d\x9a\xb6\x80\x2e\x1b\xc7\x13\x7c\x69\x54\x96\x14\x1b\x64\xa8\x70\x74\x32\xc4\xe9\x97\x52\x4e\x59\x42\x67\x19\x06\x48\x46\xb9\xf8\x28\xeb\xca\x37\xf8\x46\x9e\xa4\x8d\x8b\xb7\x6b\x54\xe6\x89\xbe\x83\xe7\x64\x73\x16\x1f\x45\x6d\x59\xad\xa9\x64\x37\x5c\x08\xbd\xe6\xd7\x09\xf4\x84\x96\x99\x5d\x51\x49\x8d\xd1\xc3\xdf\x0c\x15\x93\x64\xa1\x42\xc1\x6b\x6c\xb8\x5d\xf0\xac\x07\xdb\xe1\x9e\x2c\xba\xab\xdf\xf0\xda\x91\x3e\x2e\x95\xe1\x9e\xcd\x4d\xfb\xe5\x7e\x2b\x78\x1a\xc6\x6b\xdc\x89\x31\x50\x41");
	     std::string password = std::string("\x3f\x3f\x07\x67\x0c\x91\xd4\x95\x77\x6b\x28\x48\x11\xb7\xaf\x60\xb2\x91\x1b\xc3\xa2\x52\x09\xa3\xf8\x48\x9a\xe6\x47\x09\x5b\x5f\xcd\x0b\xeb\xc8\xca\xff\x0b\x89\xef\x85\x43\x78\x93\x17\x88\x25\x36\x7a\x32\xcd\xbb\x34\x23\xde\xba\x21\x3d\x65\xfe\x47\x5f\x62\xcb\x3c\x6b\xa4\x79\x03\x3a\x82\x0e\x3b\x6c\x65\x51\xdb\x88\x22\x49\x5e\x88\xc6\xc6\xc6\x1c\x9e\x99\x83\xf6\xfb\x8f\x5d\x90\x1c\xc0\x8b\x27\x2d\x2a\x65\x29\x53\x05\x0b\xb6\x40\x33\x2e\x76\xf1\xaf\xb6\x91\xc2\x98\x56\x8b\x18\x6e\xf2\x07\x51\x55\x84\x2c\x97");
	     bool user_identify_token_found = false;

	     for (auto ep : createSessionResponse.Parameters.ServerEndpoints)
	       {
	         if (ep.SecurityMode == MessageSecurityMode::None)
	           {
	             for (auto token : ep.UserIdentityTokens)
	               {
	                 if (user.empty())
	                   {
	                     if (token.TokenType == UserTokenType::Anonymous)
	                       {
	                         sessionParameters.UserIdentityToken.setPolicyId(token.PolicyId);
	                         user_identify_token_found = true;
	                         break;
	                       }
	                   }

	                 else
	                   {
	                     if (token.TokenType == UserTokenType::UserName)
	                       {
	  //                       sessionParameters.UserIdentityToken.setPolicyId(token.PolicyId);
	                         sessionParameters.UserIdentityToken.setPolicyId("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15");

	                         sessionParameters.UserIdentityToken.setUser(user, password);
	                        // EncryptPassword(sessionParameters.UserIdentityToken, createSessionResponse);
	                         user_identify_token_found = true;
	                         break;
	                       }
	                   }
	               }
	           }
	       }

	     if (!user_identify_token_found)
	       {
	         throw std::runtime_error("Cannot find suitable user identify token for session");
	       }
	   }
	   ActivateSessionResponse aresponse = Server->ActivateSession(sessionParameters);
	   CheckStatusCode(aresponse.Header.ServiceResult);

	   LOG_INFO(Logger, "ua_client             | activate session OK");

	   if (createSessionResponse.Parameters.RevisedSessionTimeout > 0 && createSessionResponse.Parameters.RevisedSessionTimeout < DefaultTimeout)
	     {
	       DefaultTimeout = createSessionResponse.Parameters.RevisedSessionTimeout;
	     }

	   KeepAlive.Start(Server, Node(Server, ObjectId::Server_ServerStatus_State), DefaultTimeout);
}

void UaClient::Connect(const EndpointDescription & endpoint)
{
  Endpoint = endpoint;
  const Common::Uri serverUri(Endpoint.EndpointUrl);
  OpcUa::IOChannel::SharedPtr channel = OpcUa::Connect(serverUri.Host(), serverUri.Port(), Logger);

  OpcUa::SecureConnectionParams params;
  params.EndpointUrl = Endpoint.EndpointUrl;
  params.SecurePolicy = "http://opcfoundation.org/UA/SecurityPolicy#None";

  Server = OpcUa::CreateBinaryClient(channel, params, Logger);

  OpenSecureChannel();


  LOG_INFO(Logger, "ua_client             | creating session ...");

  OpcUa::RemoteSessionParameters session;
  session.ClientDescription.ApplicationUri = ApplicationUri;
  session.ClientDescription.ProductUri = ProductUri;
  session.ClientDescription.ApplicationName = LocalizedText(SessionName);
  session.ClientDescription.ApplicationType = OpcUa::ApplicationType::Client;
  session.SessionName = SessionName;
  session.EndpointUrl = endpoint.EndpointUrl;
  session.Timeout = DefaultTimeout;
  session.ServerURI = endpoint.Server.ApplicationUri;

  CreateSessionResponse createSessionResponse = Server->CreateSession(session);
  CheckStatusCode(createSessionResponse.Header.ServiceResult);

  LOG_INFO(Logger, "ua_client             | create session OK");

  LOG_INFO(Logger, "ua_client             | activating session ...");

  ActivateSessionParameters sessionParameters;
  {
    //const SessionData &session_data = response.Session;
    Common::Uri uri(session.EndpointUrl);
    std::string user = uri.User();
    std::string password = uri.Password();
    //password = std::string("\x5f\x1f\x03\xf6\x88\x5d\x9a\xb6\x80\x2e\x1b\xc7\x13\x7c\x69\x54\x96\x14\x1b\x64\xa8\x70\x74\x32\xc4\xe9\x97\x52\x4e\x59\x42\x67\x19\x06\x48\x46\xb9\xf8\x28\xeb\xca\x37\xf8\x46\x9e\xa4\x8d\x8b\xb7\x6b\x54\xe6\x89\xbe\x83\xe7\x64\x73\x16\x1f\x45\x6d\x59\xad\xa9\x64\x37\x5c\x08\xbd\xe6\xd7\x09\xf4\x84\x96\x99\x5d\x51\x49\x8d\xd1\xc3\xdf\x0c\x15\x93\x64\xa1\x42\xc1\x6b\x6c\xb8\x5d\xf0\xac\x07\xdb\xe1\x9e\x2c\xba\xab\xdf\xf0\xda\x91\x3e\x2e\x95\xe1\x9e\xcd\x4d\xfb\xe5\x7e\x2b\x78\x1a\xc6\x6b\xdc\x89\x31\x50\x41");
    password = std::string("\x3f\x3f\x07\x67\x0c\x91\xd4\x95\x77\x6b\x28\x48\x11\xb7\xaf\x60\xb2\x91\x1b\xc3\xa2\x52\x09\xa3\xf8\x48\x9a\xe6\x47\x09\x5b\x5f\xcd\x0b\xeb\xc8\xca\xff\x0b\x89\xef\x85\x43\x78\x93\x17\x88\x25\x36\x7a\x32\xcd\xbb\x34\x23\xde\xba\x21\x3d\x65\xfe\x47\x5f\x62\xcb\x3c\x6b\xa4\x79\x03\x3a\x82\x0e\x3b\x6c\x65\x51\xdb\x88\x22\x49\x5e\x88\xc6\xc6\xc6\x1c\x9e\x99\x83\xf6\xfb\x8f\x5d\x90\x1c\xc0\x8b\x27\x2d\x2a\x65\x29\x53\x05\x0b\xb6\x40\x33\x2e\x76\xf1\xaf\xb6\x91\xc2\x98\x56\x8b\x18\x6e\xf2\x07\x51\x55\x84\x2c\x97");
    bool user_identify_token_found = false;

    for (auto ep : createSessionResponse.Parameters.ServerEndpoints)
      {
        if (ep.SecurityMode == MessageSecurityMode::None)
          {
            for (auto token : ep.UserIdentityTokens)
              {
                if (user.empty())
                  {
                    if (token.TokenType == UserTokenType::Anonymous)
                      {
                        sessionParameters.UserIdentityToken.setPolicyId(token.PolicyId);
                        user_identify_token_found = true;
                        break;
                      }
                  }

                else
                  {
                    if (token.TokenType == UserTokenType::UserName)
                      {
 //                       sessionParameters.UserIdentityToken.setPolicyId(token.PolicyId);
                        sessionParameters.UserIdentityToken.setPolicyId("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15");

                        sessionParameters.UserIdentityToken.setUser(user, password);
                       // EncryptPassword(sessionParameters.UserIdentityToken, createSessionResponse);
                        user_identify_token_found = true;
                        break;
                      }
                  }
              }
          }
      }

    if (!user_identify_token_found)
      {
        throw std::runtime_error("Cannot find suitable user identify token for session");
      }
  }
  ActivateSessionResponse aresponse = Server->ActivateSession(sessionParameters);
  CheckStatusCode(aresponse.Header.ServiceResult);

  LOG_INFO(Logger, "ua_client             | activate session OK");

  if (createSessionResponse.Parameters.RevisedSessionTimeout > 0 && createSessionResponse.Parameters.RevisedSessionTimeout < DefaultTimeout)
    {
      DefaultTimeout = createSessionResponse.Parameters.RevisedSessionTimeout;
    }

  KeepAlive.Start(Server, Node(Server, ObjectId::Server_ServerStatus_State), DefaultTimeout);
}

void UaClient::OpenSecureChannel()
{
  OpenSecureChannelParameters channelparams;
  channelparams.ClientProtocolVersion = 0;
  channelparams.RequestType = SecurityTokenRequestType::Issue;
  channelparams.SecurityMode = MessageSecurityMode::None;
  channelparams.ClientNonce = std::vector<uint8_t>(1, 0);
  channelparams.RequestLifeTime = DefaultTimeout;
  const OpenSecureChannelResponse & response = Server->OpenSecureChannel(channelparams);

  CheckStatusCode(response.Header.ServiceResult);

  SecureChannelId = response.ChannelSecurityToken.SecureChannelId;

  if (response.ChannelSecurityToken.RevisedLifetime > 0)
    {
      DefaultTimeout = response.ChannelSecurityToken.RevisedLifetime;
    }
}

void UaClient::CloseSecureChannel()
{
  Server->CloseSecureChannel(SecureChannelId);
}

UaClient::~UaClient()
{
  Disconnect();//Do not leave any thread or connection running
}

void UaClient::Disconnect()
{
  KeepAlive.Stop();

  if (Server.get())
    {
      CloseSessionResponse response = Server->CloseSession();

      LOG_INFO(Logger, "ua_client             | CloseSession response is {}", ToString(response.Header.ServiceResult));

      CloseSecureChannel();
      Server.reset();
    }

}

void UaClient::Abort()
{
  KeepAlive.Stop();

  Server.reset(); //FIXME: check if we still need this
}

std::vector<std::string>  UaClient::GetServerNamespaces()
{
  if (!Server) { throw std::runtime_error("Not connected");}

  Node namespacearray(Server, ObjectId::Server_NamespaceArray);
  return namespacearray.GetValue().As<std::vector<std::string>>();;
}

uint32_t UaClient::GetNamespaceIndex(std::string uri)
{
  if (!Server) { throw std::runtime_error("Not connected");}

  Node namespacearray(Server, ObjectId::Server_NamespaceArray);
  std::vector<std::string> uris = namespacearray.GetValue().As<std::vector<std::string>>();;

  for (uint32_t i = 0; i < uris.size(); ++i)
    {
      if (uris[i] == uri)
        {
          return i;
        }
    }

  throw std::runtime_error("Error namespace uri does not exists in server");
  //return -1;
}


Node UaClient::GetNode(const std::string & nodeId) const
{
  return Node(Server, ToNodeId(nodeId));
}

Node UaClient::GetNode(const NodeId & nodeId) const
{
  if (!Server) { throw std::runtime_error("Not connected");}

  return Node(Server, nodeId);
}

Node UaClient::GetRootNode() const
{
  if (!Server) { throw std::runtime_error("Not connected");}

  return Node(Server, OpcUa::ObjectId::RootFolder);
}

Node UaClient::GetObjectsNode() const
{
  if (!Server) { throw std::runtime_error("Not connected");}

  return Node(Server, OpcUa::ObjectId::ObjectsFolder);
}

Node UaClient::GetServerNode() const
{
  if (!Server) { throw std::runtime_error("Not connected");}

  return Node(Server, OpcUa::ObjectId::Server);
}

void UaClient::DeleteNodes(std::vector<OpcUa::Node> & nodes, bool recursive)
{
  if (recursive)
    {
      std::vector<OpcUa::Node> children = AddChilds(nodes);
      nodes.insert(nodes.end(), children.begin(), children.end());
    }

  LOG_DEBUG(Logger, "ua_client             | deleting nodes ...");

  std::vector<OpcUa::DeleteNodesItem> nodesToDelete;
  nodesToDelete.resize(nodes.size());

  for (unsigned i = 0; i < nodes.size(); i++)
    {
      nodesToDelete[i].NodeId = nodes[i].GetId();
      nodesToDelete[i].DeleteTargetReferences = true;
    }

  DeleteNodesResponse response = Server->DeleteNodes(nodesToDelete);

  for (std::vector<OpcUa::StatusCode>::iterator it = response.Results.begin(); it < response.Results.end(); it++)
    {
      CheckStatusCode(*it);
    }
}

std::vector<OpcUa::Node> UaClient::AddChilds(std::vector<OpcUa::Node> nodes)
{
  std::vector<OpcUa::Node> results;
  std::vector<OpcUa::Node> temp;

  for (std::vector<OpcUa::Node>::iterator it = nodes.begin(); it < nodes.end(); it++)
    {
      temp.clear();
      temp = it->GetChildren();

      if (!temp.empty())
        {
          results.insert(results.begin(), temp.begin(), temp.end());
          temp = AddChilds(temp);
          results.insert(results.begin(), temp.begin(), temp.end());
        }
    }

  return results;
}

Subscription::SharedPtr UaClient::CreateSubscription(unsigned int period, SubscriptionHandler & callback)
{
  CreateSubscriptionParameters params;
  params.RequestedPublishingInterval = period;

  return std::make_shared<Subscription>(Server, params, callback, Logger);
}

ServerOperations UaClient::CreateServerOperations()
{
  return ServerOperations(Server);
}

void UaClient::EncryptPassword(OpcUa::UserIdentifyToken &identity, const CreateSessionResponse &response)
{
  if(response.Parameters.ServerCertificate.Data.empty() || response.Parameters.ServerNonce.Data.empty()) {
    // server response does not contain information needed to encrypt password
    return;
  }
#ifdef SSL_SUPPORT_MBEDTLS
  // use RSA-OAEP encryption if server certificate and nounce is provided
  LOG_DEBUG(Logger, "ua_client             | encrypting password RSA-OAEP");
  auto error2string = [](int err_no) -> std::string
  {
    auto int_to_hex = [](u_int16_t i) -> std::string
    {
      std::stringstream stream;
      stream << std::setfill ('0') << std::setw(sizeof(i)*2) << std::hex << i;
      return stream.str();
    };

    char buff[1024];
    mbedtls_strerror(err_no, buff, sizeof(buff));
    return "-" + int_to_hex(-err_no) + ": " + std::string(buff);
  };
  auto hex = [](const std::vector<unsigned char> &bytes)
  {
    std::string ret;
    for(unsigned char c : bytes) {
      auto val_to_digit = [](unsigned char c) { return (c >= 10)? c-10+'a': c+'0'; };
      ret.push_back(val_to_digit(c/16));
      ret.push_back(val_to_digit(c%16));
    }
    return ret;
  };
  mbedtls_x509_crt x509;
  mbedtls_x509_crt_init( &x509 );
  LOG_DEBUG(Logger, "ua_client             | loading server certificate ... {}", hex(response.Parameters.ServerCertificate.Data));
  int ret = mbedtls_x509_crt_parse_der( &x509, response.Parameters.ServerCertificate.Data.data(), response.Parameters.ServerCertificate.Data.size());
  if( ret != 0 ) {
    LOG_ERROR(Logger, "ua_client             | error loading server certificate {}", error2string(ret) );
    goto exit1;
  }
  {
      mbedtls_entropy_context entropy;
      mbedtls_ctr_drbg_context ctr_drbg;
      const char pers[] = "freeopcua_ua_client";

      mbedtls_ctr_drbg_init( &ctr_drbg );
      mbedtls_entropy_init( &entropy );

      LOG_DEBUG(Logger, "ua_client             | seeding the random number generator...");
      ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, sizeof(pers) );
      if( ret != 0 ) {
        LOG_ERROR(Logger, "ua_client             | error seeding the random number generator {}", error2string(ret) );
        goto exit2;
      }
      {
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa(x509.pk);
        rsa->padding = MBEDTLS_RSA_PKCS_V21;
        rsa->hash_id = MBEDTLS_MD_SHA1;

        LOG_DEBUG(Logger, "ua_client             | generating the RSA encrypted value...");

        unsigned char buff[rsa->len];
        std::string input = identity.UserName.Password;
        input += std::string(response.Parameters.ServerNonce.Data.begin(), response.Parameters.ServerNonce.Data.end());
        {
          std::string sn(4, '\0');
          size_t l = input.length();
          for (size_t i = 0; i < l; ++i) {
            unsigned char n = l % 256;
            l /= 256;
            sn[i] = n;
          }
          input = sn + input;
        }

        ret = mbedtls_rsa_pkcs1_encrypt( rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, input.size(), (const unsigned char*)input.data(), buff );
        if( ret != 0 ) {
          LOG_ERROR(Logger, "ua_client             | error RSA encryption {}", error2string(ret) );
          goto exit2;
        }
        LOG_DEBUG(Logger, "ua_client             | encrypted password: {}", hex(std::vector<unsigned char>(buff, buff + sizeof(buff))));

        identity.UserName.Password = std::string((const char*)buff, rsa->len);
        identity.UserName.EncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#rsa-oaep";
      }
exit2:
      mbedtls_ctr_drbg_free( &ctr_drbg );
      mbedtls_entropy_free( &entropy );
  }
exit1:
  mbedtls_x509_crt_free( &x509 );
#endif
}

} // namespace OpcUa

