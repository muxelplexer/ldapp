#include "ldapp/entry.hpp"


namespace ldapp
{
    entry::entry(LDAP* ldap, message_ptr msg)
    {
        
    }
    
    entry::entry(LDAP* ldap, LDAPMessage* msg)
    {
        berval* bvals = nullptr;
        berelement* ber = nullptr;
        berval** bvalsp = &bvals;
        berval bv{};
        auto rc = handle_ldap_function(
            ldap_get_dn_ber,
            ldap,
            msg,
            &ber,
            &bv
        );


        for (rc = handle_ldap_function(ldap_get_attribute_ber, ldap, msg, ber, &bv, bvalsp);
             bv.bv_val != nullptr;
             rc = handle_ldap_function(ldap_get_attribute_ber, ldap, msg, ber, &bv, bvalsp))
        {
            if (bvals)
            {
                for (auto i = 0; bvals[i].bv_val != nullptr; ++i)
                {
                    this->m_Attributes.emplace_back(std::string(bv.bv_val), std::string(bvals[i].bv_val));
                }
            }
            ber_memfree(bvals);
        }

        ber_free(ber, 0);
    }

    entry::entry(const entry& entry)
        : m_Attributes{entry.m_Attributes}
    {

    }

    entry::entry(entry&& entry) noexcept
        : m_Attributes{std::move(entry.m_Attributes)}
    {
    }

    entry::~entry()
    {
    }
}