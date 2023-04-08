#pragma once 
#include "result.hpp"
#include "exception.hpp"
#include <memory>

namespace ldapp
{
    struct ldap_message_deleter
    {
        void operator()(LDAPMessage* msg) { ldap_msgfree(msg); };
    };
    using message_ptr = std::unique_ptr<LDAPMessage, ldap_message_deleter>;
    inline result handle_ldap_function(auto function, auto... args)
    {
        result rc = static_cast<result>(function(
            std::forward<decltype(args)>(args)...
        ));

        if (results::is_error(rc)) throw ldapp::exception(rc);
        return rc;
    }
}