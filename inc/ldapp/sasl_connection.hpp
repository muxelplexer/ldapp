#pragma once
#include <ldap.h>
#include <string>
#include <string_view>

namespace ldapp
{
    class sasl_connection
    {
        public:
            sasl_connection(LDAP* ldap, const std::string_view binddn, const std::string& password);

            const std::string& get_binddn() const { return this->m_Binddn; };

        private:
            LDAP* m_LDAP = nullptr;
            std::string m_Binddn;

    };
}