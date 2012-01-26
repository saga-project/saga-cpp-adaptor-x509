//  Copyright (c) 2009 Ole Weidner (oweidner@cct.lsu.edu)
// 
//  Distributed under the Boost Software License, Version 1.0. (See accompanying 
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include "x509_context_adaptor.hpp"

#include <unistd.h>

#include <saga/saga/adaptors/config.hpp>
#include <saga/saga/adaptors/adaptor.hpp>
#include <saga/saga/adaptors/attribute.hpp>

#include <boost/filesystem/operations.hpp>
#include <boost/format.hpp>

using namespace x509_context_adaptor;

#define ADAPTORS_X509_CONTEXT_TYPE "x509"

SAGA_ADAPTOR_REGISTER (context_adaptor);

///////////////////////////////////////////////////////////////////////////////
//  constructor
context_cpi_impl::context_cpi_impl (proxy                * p, 
                                    cpi_info       const & info,
                                    saga::ini::ini const & glob_ini, 
                                    saga::ini::ini const & adap_ini,
                                    TR1::shared_ptr <saga::adaptor> adaptor)
    : base_cpi (p, info, adaptor, cpi::Noflags)
{
  saga::adaptors::attribute attr (this);

  if ( attr.attribute_exists (saga::attributes::context_type) )
  {
    if ( ADAPTORS_X509_CONTEXT_TYPE != 
         attr.get_attribute (saga::attributes::context_type) )
    {
      SAGA_OSSTREAM strm;
      strm << "Can't handle context with type '" 
           << attr.get_attribute(saga::attributes::context_type) << "'."
            << "This adaptor only supports 'ADAPTORS_X509_CONTEXT_TYPE' contexts.";

      SAGA_ADAPTOR_THROW (SAGA_OSSTREAM_GETSTRING(strm), saga::BadParameter);
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
//  destructor
context_cpi_impl::~context_cpi_impl (void)
{
}

///////////////////////////////////////////////////////////////////////////////
//
void context_cpi_impl::sync_set_defaults (saga::impl::void_t &)
{    
  saga::adaptors::attribute attr (this);
 
  if ( attr.attribute_exists (saga::attributes::context_type) )
  {
    if ( ADAPTORS_X509_CONTEXT_TYPE != 
         attr.get_attribute (saga::attributes::context_type) )
    {
      SAGA_OSSTREAM strm;
      strm << "Can't handle context with type '" 
           << attr.get_attribute(saga::attributes::context_type) << "'."
           << "This adaptor only supports 'ADAPTORS_X509_CONTEXT_TYPE' contexts.";

      SAGA_ADAPTOR_THROW (SAGA_OSSTREAM_GETSTRING(strm), saga::BadParameter);
    }

    cert_info_t ci;

    if ( attr.attribute_exists (saga::attributes::context_userproxy) ) 
    {
      // this call looks for a valid proxy file in the location described by
      // saga::attributes::context_userproxy
      SAGA_OSSTREAM strm;
      strm << "UserProxy attribute set to: " 
           << attr.get_attribute(saga::attributes::context_userproxy);
      SAGA_LOG_INFO(strm.str());

      ci = get_cert_info (attr.get_attribute (saga::attributes::context_userproxy));
    }
    else
    {
      // try to find a valid certfile either in X509_USER_PROXY or in /tmp/
      const char* _cert;
      std::string certfile;
      
      if(!(_cert = saga::detail::safe_getenv("X509_USER_PROXY"))) 
      {
        std::string tmp = "/tmp/x509up_u";
        certfile = (std::string&)tmp + boost::str( boost::format("%d") % ::getuid() );

        SAGA_OSSTREAM strm;
        strm << "UserProxy attribute not set. "
                    << "Using default location: " << certfile;
        SAGA_LOG_INFO(strm.str());
      } 
      else 
      {
        SAGA_OSSTREAM strm;
        strm << "UserProxy attribute not set. Using " 
                    << "X509_USER_PROXY env variable: " << _cert;
        SAGA_LOG_INFO(strm.str());

        certfile = _cert;
      }
      // settting the userproxy path attribute
      attr.set_attribute (saga::attributes::context_userproxy, certfile);

      ci = get_cert_info(certfile);
    }

    if ( true == ci.success )
    {
      // found a valid cert, copy information over
      // attr.set_attribute (saga::attributes::context_userproxy, ci.path);
      // attr.set_attribute (saga::attributes::context_userid,    ci.identity);
      // ...
    }
    else
    {
        SAGA_OSSTREAM strm;
        strm << ci.errormessage << std::endl;
        SAGA_LOG_WARN(strm.str());
    }
  }
}
//
///////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
//
saga::impl::adaptor_selector::adaptor_info_list_type
context_adaptor::adaptor_register (saga::impl::session * s)
{
  // list of implemented cpi's
  saga::impl::adaptor_selector::adaptor_info_list_type infos;
  preference_type prefs; 

  context_cpi_impl::register_cpi (infos, prefs, adaptor_uuid_);

  // create a default security context if this is a default session
  if ( s->is_default_session () )
  {
    std::vector <std::pair <std::string, std::string> > entries;

    std::pair <std::string, std::string> entry (saga::attributes::context_type, 
                                                ADAPTORS_X509_CONTEXT_TYPE);
    entries.push_back (entry);

    s->add_proto_context (entries);

  }

  return infos;
}
//
///////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
//
// init a cert, either from a given path, or from a default location
//
cert_info_t context_cpi_impl::get_cert_info (std::string path)
{
  // Right now, we can only check if the path exists. More certificate checks
  // can be performed as soons as we decide which api we want to use to handle 
  // x509 certificates. 
  cert_info_t ci;

  ci.success      = false;
  ci.errormessage = "";
  
  if(!boost::filesystem::exists(path)) {
    ci.success = false;
    ci.errormessage = "X.509 UserProxy path '" + path + "' does not exist.";
  }
  
  return ci;
}
//
///////////////////////////////////////////////////////////////////////////////

