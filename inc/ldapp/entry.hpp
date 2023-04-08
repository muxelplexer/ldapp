#pragma once
#include <ldap.h>
#include <memory>
#include <vector>
#include "attribute.hpp"
#include "utility.hpp"

namespace ldapp
{
    class entry
    {
    public:
        entry(LDAP* ldap, message_ptr msg);
        entry(LDAP* ldap, LDAPMessage* msg);
        entry(const entry& entry);
        entry(entry&& entry) noexcept;
        ~entry();

        const entry& operator=(const entry& e)
        {
            return *this = entry(e);
        }
        entry& operator=(entry&& e) noexcept
        {
            return *this = entry(e);
        }

        [[nodiscard]] const std::vector<attribute>& get_attributes() const { return this->m_Attributes; };

    private:
        std::vector<attribute> m_Attributes{};
    };
}