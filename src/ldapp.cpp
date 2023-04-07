#include "ldapp/ldapp.hpp"
#include <stdexcept>
#include <iostream>


namespace ldapp
{
    instance::instance(const std::string_view ldap_path, const std::string_view binddn, const std::string_view password)
        : m_Ptr{std::move(instance::initialize(ldap_path))}
    {
        int ldap_version = 3;
        ldap_set_option(this->m_Ptr.get(), LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
        this->connect();
        this->sasl_bind(binddn, password);
    }

    void instance::connect()
    {
        result rc{ldap_connect(this->m_Ptr.get())};
        if (results::is_error(rc)) throw ldapp::exception(rc);
        this->m_Connected = true;
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
    void instance::sasl_bind(const std::string_view binddn, const std::string_view password)
    {
        if (!this->m_Connected) throw std::runtime_error("Can't bind: No connection is opened");
        try
        {
            this->m_Con = std::make_unique<sasl_connection>(
                this->m_Ptr.get(),
                binddn,
                std::move(std::string(password))
            );
            this->m_Bound = true;
        }
        catch(const std::runtime_error& e)
        {
            std::cerr << e.what() << '\n';
        }
        

    }

    void instance::search(const std::string& searchdn, const std::string_view search_filter)
    {
        using namespace std::literals;
        LDAPMessage* res = nullptr;
        timeval timeout{.tv_sec = 15};

        std::string filter{"(objectClass="sv};
        filter += search_filter;
        filter += ")";

        handle_ldap_function(
            ldap_search_ext_s,
            this->m_Ptr.get(),
            searchdn.c_str(),
            LDAP_SCOPE_SUBTREE,
            filter.c_str(),
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

    ldap_ptr instance::initialize(const std::string_view ldap_path)
    {
        LDAP* ptr = nullptr;
        
        if(ldap_initialize(&ptr, ldap_path.data()) != LDAP_SUCCESS) throw std::runtime_error("Could not initialize LDAP Connection...");
        return ldap_ptr(ptr);
    }


}