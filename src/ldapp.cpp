#include "ldapp/ldapp.hpp"
#include <stdexcept>
#include <iostream>
#include "ldapp/entry.hpp"
#include "ldapp/utility.hpp"


namespace ldapp
{
    instance::instance(const std::string_view ldap_path, const std::string_view binddn, const std::string_view password)
        : m_Ptr{std::move(ldap_ptr(instance::initialize(ldap_path)))}
    {
        int ldap_version = 3;
        ldap_set_option(this->m_Ptr.get(), LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
        this->connect();
        this->sasl_bind(binddn, password);
    }

    void instance::connect()
    {
        handle_ldap_function(ldap_connect, this->m_Ptr.get());
        this->m_Connected = true;
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

        auto msg_ptr = message_ptr(std::move(res));

        int res_count = 0;
        std::vector<entry> entries{};
        for (auto msg = ldap_first_message(this->m_Ptr.get(), msg_ptr.get());
                  msg != nullptr;
                  msg = ldap_next_message(this->m_Ptr.get(), msg))
        {
            if (msg == nullptr) break;
            switch (ldap_msgtype(msg))
            {
            case 100:
                entries.emplace_back(this->m_Ptr.get(), msg);
                break;
            default:
                break;
            }
        }

        for (auto& entry : entries)
        {
            std::cout << "New Entry:\n";
            for (auto& attr : entry.get_attributes())
            {
                std::cout << attr.get_name() << "=" << attr.get_value() << "\n";
            }
            std::cout << "\n";
        }
    }

    LDAP* instance::initialize(const std::string_view ldap_path)
    {
        LDAP* ptr = nullptr;
        const std::string ldap_path_s{ldap_path};
        if(ldap_initialize(&ptr, ldap_path_s.c_str()) != LDAP_SUCCESS) throw std::runtime_error("Could not initialize LDAP Connection...");
        return ptr;
    }


}