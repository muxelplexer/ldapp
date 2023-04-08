#include "ldapp/sasl_connection.hpp"
#include "ldapp/result.hpp"
#include "ldapp/exception.hpp"
#include "ldapp/utility.hpp"

namespace ldapp
{
    sasl_connection::sasl_connection(LDAP* ldap, const std::string_view binddn, const std::string& password)
        :m_LDAP{ldap}, m_Binddn{binddn}
    {
        berval passwd;
        passwd.bv_val = ber_strdup(password.c_str());
        passwd.bv_len = strlen(passwd.bv_val);

        handle_ldap_function(
            ldap_sasl_bind_s,
            this->m_LDAP,
            this->m_Binddn.c_str(),
            LDAP_SASL_SIMPLE,
            &passwd,
            nullptr,
            nullptr,
            nullptr
        );

        free(passwd.bv_val);
    }
}