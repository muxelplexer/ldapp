#include "ldapp/ldapp.hpp"
#include <stdexcept>
#include <iostream>


namespace ldapp
{
    instance::instance(const std::string_view ldap_path)
        : m_Ptr{std::move(instance::initialize(ldap_path))}
    {
        int ldap_version = 3;
        ldap_set_option(this->m_Ptr.get(), LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
        this->sasl_bind();
    }

    void instance::connect()
    {
        result rc{ldap_connect(this->m_Ptr.get())};
        if (results::is_error(rc)) throw ldapp::exception(rc);
    }

    void instance::print_entry(LDAPMessage* entry)
    {
        berelement* ber;
        berval* bvals;
        berval** bvalsp = &bvals;
        berval bv;
        auto rc = handle_ldap_function(
            ldap_get_dn_ber,
            this->m_Ptr.get(),
            entry,
            &ber,
            &bv
        );
        for (rc = handle_ldap_function(ldap_get_attribute_ber, this->m_Ptr.get(), entry, ber, &bv, bvalsp);
             rc == result::SUCCESS;
             rc == handle_ldap_function(ldap_get_attribute_ber, this->m_Ptr.get(), entry, ber, &bv, bvalsp))
        {
            if (bv.bv_val == nullptr) break;
            for (auto i = 0; bvals[i].bv_val != nullptr; ++i)
            {
                std::cout << "\t" <<  bv.bv_val << ": \"" << bvals[i].bv_val << "\"\n";
            }

        }
    }
    void instance::sasl_bind()
    {
        LDAPControl* srv_ctr = nullptr;
        LDAPControl* clt_ctr = nullptr;
        LDAPMessage* message = nullptr;
        int msgid = 0;
        const char* rmech = nullptr;

        result rc;
        std::string_view password{};
        berval  passwd;
        berval* servercred;
        passwd.bv_val = ber_strdup(password.begin());
        passwd.bv_len = strlen(passwd.bv_val);

        handle_ldap_function(
            ldap_sasl_bind_s,
            this->m_Ptr.get(),
            "",
            LDAP_SASL_SIMPLE,
            &passwd,
            &srv_ctr,
            &clt_ctr,
            &servercred
        );

        this->m_SCtrl = control_ptr(std::move(srv_ctr));
        this->m_CCtrl = control_ptr(std::move(clt_ctr));

        LDAPMessage* res = nullptr;
        timeval timeout{.tv_sec = 15};

        handle_ldap_function(
            ldap_search_ext_s,
            this->m_Ptr.get(),
            "",
            LDAP_SCOPE_SUBTREE,
            "(objectClass=*)",
            nullptr,
            0,
            nullptr,
            nullptr,
            &timeout,
            0,
            &res
        );

        int res_count = 0;
        for (auto msg = ldap_first_message(this->m_Ptr.get(), res);
                  msg != nullptr;
                  msg = ldap_next_message(this->m_Ptr.get(), msg))
        {
            std::cout << "Object:\n";
            print_entry(msg);
        }
    }

    void instance::sasl_unbind()
    {

    }



    ldap_ptr instance::initialize(const std::string_view ldap_path)
    {
        LDAP* ptr = nullptr;
        
        if(ldap_initialize(&ptr, ldap_path.data()) != LDAP_SUCCESS) throw std::runtime_error("Could not initialize LDAP Connection...");
        return ldap_ptr(ptr);
    }


}